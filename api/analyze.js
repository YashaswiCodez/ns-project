const https = require('https');

export default function handler(req, res) {
    if (req.method !== 'POST') {
        res.status(405).send({ Error: 'Method not allowed' });
        return;
    }

    const domain = req.body.domain || req.query.domain;
    if (!domain) {
        res.status(400).json({ Error: 'No domain provided' });
        return;
    }

    const options = {
        hostname: domain,
        port: 443,
        method: 'GET',
    };

    const reqTLS = https.request(options, (response) => {
        const cert = response.socket.getPeerCertificate();
        if (!cert) {
            res.status(500).json({ Error: 'No certificate found' });
            return;
        }

        const validFrom = new Date(cert.valid_from).toISOString().split('T')[0];
        const validTo = new Date(cert.valid_to).toISOString().split('T')[0];
        const daysLeft =
            (new Date(cert.valid_to) - new Date()) / (1000 * 60 * 60 * 24);

        res.status(200).json({
            Subject: cert.subject,
            Issuer: cert.issuer,
            'Valid From': validFrom,
            'Valid To': validTo,
            'Is Valid': daysLeft > 0,
            'Days Left': Math.max(Math.floor(daysLeft), 0),
        });
    });

    reqTLS.on('error', (error) => {
        res.status(500).json({ Error: error.message });
    });

    reqTLS.end();
}
