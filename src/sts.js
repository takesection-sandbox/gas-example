const Signature = require('./signature-v4');

class Sts {

    constructor(access_key_id, secret_access_key, region) {
        this.service = 'sts';
        this.region = region ? region : 'us-east-1';

        this.signature = new Signature(this.service, this.region, access_key_id, secret_access_key);
    }
    
    assumeRole(expireIn, signingDate, role_arn, role_session_name) {
        const request = {
            method: 'GET',
            protocol: 'https:',
            path: '/',
            headers: {
                host: `${this.service}.${this.region}.amazonaws.com`
            },
            query: {
                'Action': 'AssumeRole',
                'Version': '2011-06-15',
                'RoleArn': role_arn,
                'RoleSessionName': role_session_name
            },
            hostname: `${this.service}.${this.region}.amazonaws.com`,
        };
        return this.signature.presign(expireIn, signingDate, request);
    }
}

module.exports = Sts;
