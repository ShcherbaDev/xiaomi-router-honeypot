# Xiaomi router honeypot

Replicates the login page of the MiWi-Fi Router.

On login requests, it always throws an invalid credentials error, sends an email notification, and logs client information into a file.

## Screenshots

Original MiWi-Fi page:

![[docs/original.png]]

Local page (look at the URL address):

![[docs/local.png]]

## Set up

1. Clone the repository
2. Install dependencies with `npm install`
3. In project root, create a `.env` file with these values:

```
EMAIL_ADDRESS=YOUR_EMAIL
EMAIL_PASSWORD=YOUR_EMAIL_APP_PASSWORD
```

Note: if you use Gmail as an email provider, generate an app password here: <https://myaccount.google.com/apppasswords>

3. Run `npm start`
