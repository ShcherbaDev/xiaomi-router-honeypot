import express from 'express';
import nodemailer from 'nodemailer';
import { toMAC } from '@network-utils/arp-lookup';
import { appendFile } from 'fs/promises';
import 'dotenv/config';

const logFilename = 'requests.log';

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

const port = 3000;
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
	const mac = await toMAC(ip);

	const logMessage = `${new Date().toISOString()} INCOMING REQUEST: ${ip}; ${mac}; ${userAgent}; ${JSON.stringify(body)}`;
	console.log(logMessage);

	try
	{
		await appendFile(logFilename, logMessage + '\n');
	}
	catch (error) {
		console.log(`Logging to a file error: ${error}`);
	}

	mailTransporter.sendMail({
		from: process.env.EMAIL_ADDRESS,
		to: 'andrey.shcherbakov05@gmail.com',
		subject: 'INCOMING REQUEST TO HONEYPOT',
		html: `<h1>INCOMING REQUEST</h1>
		<p>Somebody tried to sign in into the router dashboard:</p>
		<ul>
			<li><b>Timestamp:</b> ${new Date().toISOString()}</li>
			<li><b>IP:</b> ${ip}</li>
			<li><b>MAC:</b> ${mac}</li>
			<li><>User Agent:</b> ${userAgent}</li>
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

app.listen(port, '0.0.0.0');
console.log(`App is listening on port ${port}`);
