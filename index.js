import net from 'net';
import express from 'express';
import nodemailer from 'nodemailer';
import { toMAC } from '@network-utils/arp-lookup';
import { appendFile } from 'fs/promises';
import 'dotenv/config';

const loginLogFilename = 'logins.log';
const scanLogFilename = 'scans.log';
const scanInactivityTimerMilliseconds = 5000;
const scanMinPortsDetection = 3;

const mailTransporter = nodemailer.createTransport({
	service: 'gmail',
	host: 'smtp.gmail.com',
	port: '465',
	ssl: true,
	auth: {
		user: process.env.EMAIL_ADDRESS,
		pass: process.env.EMAIL_PASSWORD
	}
});

// =============
//  HTTP Server
// =============

const httpServerPort = 80;
const app = express();

app.use(express.static('.'));
app.use(express.static('index_files'));

app.use(express.urlencoded({ extended: true }));

// Redirect to login page
app.get('/', (request, response) => {
	response.redirect('/cgi-bin/luci/web');
});

// Sign in request handling
app.post('/cgi-bin/luci/api/xqsystem/login', async (request, response) => {
	const { ip, body, headers } = request;
	const userAgent = headers['user-agent'];
	const mac = await toMAC(ip) ?? 'MAC Unknown';
	const timestamp = new Date().toISOString();

	const logMessage = `${timestamp} INCOMING REQUEST: ${ip}; ${mac}; ${userAgent}; ${JSON.stringify(body)}`;
	console.log(logMessage);

	try
	{
		await appendFile(loginLogFilename, logMessage + '\n');
	}
	catch (error) {
		console.log(`Logging to a file error: ${error}`);
	}

	mailTransporter.sendMail({
		from: process.env.EMAIL_ADDRESS,
		to: process.env.EMAIL_SEND_TO,
		subject: 'INCOMING REQUEST TO HONEYPOT',
		html: `<h1>INCOMING REQUEST</h1>
			<p>Somebody tried to sign in into the router dashboard:</p>
			<ul>
				<li><b>Timestamp:</b> ${timestamp}</li>
				<li><b>IP:</b> ${ip}</li>
				<li><b>MAC:</b> ${mac}</li>
				<li><b>User Agent:</b> ${userAgent}</li>
				<li><b>Request body:</b> ${JSON.stringify(body)}</li>
			</ul>`
	}, (error, mail) => {
		if (error) {
			console.log(`Mail sending error: ${error}`);
			return;
		}
		console.log(`Email sent successfully: ${mail.response}`);
	});

	setTimeout(() => {
		response.json({
			code: 401,
			msg: 'not auth'
		});
	}, 1000);
});

app.listen(
	httpServerPort,
	'0.0.0.0',
	() => console.log(`App is listening on port ${httpServerPort}`)
);

// ================
//  Scan detection
// ================

const portsToScan = [...Array(1024).keys()].slice(1); // From 1 to 1023 (system ports)
const scanData = new Map();

portsToScan.forEach((port) => {
	const server = net.createServer(async (client) => {
		client.on('error', (error) => {
			if (error.code === 'ECONNRESET') {
				console.log(`Connection on port ${port} reset by ${client.remoteAddress}`);
			}
			else {
				console.error(`Socket error: ${error}`);
			}
		});

		const { remoteAddress } = client;

		if (!scanData.has(remoteAddress)) {
			scanData.set(remoteAddress, {
				ports: new Set(),
				timer: null
			});
		}

		const clientData = scanData.get(remoteAddress);
		clientData.ports.add(port);

		// Notify about scan only if client pings more then scanMinPortsDetection devices
		// and after n seconds of inactivity

		if (clientData.ports.size < scanMinPortsDetection) {
			client.end();
			return;
		}

		if (clientData.timer) {
			clearTimeout(clientData.timer);
		}

		clientData.timer = setTimeout(async () => {
			const mac = await toMAC(remoteAddress) ?? 'MAC Unknown';
			const timestamp = new Date().toISOString();
			const scannedPorts = [...clientData.ports].join(', ');

			const logMessage = `${timestamp} SCAN DETECTED FROM ${remoteAddress} (${mac}) ON PORTS ${scannedPorts}`;
			console.log(logMessage);

			try {
				await appendFile(scanLogFilename, logMessage + '\n');
			}
			catch (error) {
				console.log(`Logging to a file error: ${error}`);
			}

			mailTransporter.sendMail({
				from: process.env.EMAIL_ADDRESS,
				to: process.env.EMAIL_SEND_TO,
				subject: 'SCAN DETECTED',
				html: `<h1>SCANNING</h1>
				<p>Somebody tried to scan multiple ports:</p>
				<ul>
					<li><b>Timestamp:</b> ${timestamp}</li>
					<li><b>IP:</b> ${remoteAddress}</li>
					<li><b>MAC:</b> ${mac}</li>
					<li><b>PORTS:</b> ${scannedPorts}</li>
				</ul>`
			}, (error, mail) => {
				if (error) {
					console.log(`Mail sending error: ${error}`);
					return;
				}
				console.log(`Email sent successfully: ${mail.response}`);
			});

			scanData.delete(remoteAddress);
		}, scanInactivityTimerMilliseconds);

		client.end();
	});

	server.listen(
		port,
		'0.0.0.0'
	).on('error', (error) => {
		console.log(`Failed to start listening for scans on port ${port}: ${error}`);
	});
});

console.log(`Listening for scans on ports ${portsToScan[0]}-${portsToScan[portsToScan.length - 1]}`);
