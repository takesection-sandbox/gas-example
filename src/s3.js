const Signature = require('./signature-v4');

class S3 {

    constructor(access_key_id, secret_access_key, region, session_token) {
        this.service = 's3';
        this.region = region;
        this.session_token = session_token;
        this.signature = new Signature(this.service, this.region, access_key_id, secret_access_key);
    }
    
    putObject(signingDate, bucketName, key, contentType) {
        const request = {
            method: 'PUT',
            protocol: 'https:',
            path: key,
            headers: {
                host: `${bucketName}.${this.service}.${this.region}.amazonaws.com`,
                'Content-Type': contentType,
                'X-Amz-Content-Sha256': 'UNSIGNED-PAYLOAD',
            },
            hostname: `${bucketName}.${this.service}.${this.region}.amazonaws.com`,
        };
        if (this.session_token) {
            request.headers['X-Amz-Security-Token'] = this.session_token;
        }
        return this.signature.sign(signingDate, request);
    }
}

module.exports = S3;
