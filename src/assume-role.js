const Signature = require('./signature-v4');

class AssumeRole {

    constructor(access_key_id, secret_access_key, role_arn, role_session_name) {
        const service = 'sts';
        const region = 'ap-northeast-1';

        this.signature = new Signature(service, region, access_key_id, secret_access_key);

        this.role_arn = role_arn;
        this.role_session_name = role_session_name;

        this.request = {
            method: 'GET',
            protocol: 'https:',
            path: '/',
            headers: {
                host: `${service}.${region}.amazonaws.com`
            },
            hostname: `${service}.${region}.amazonaws.com`,
            query: {
                'Action': 'AssumeRole',
                'Version': '2011-06-15',
                'RoleArn': role_arn,
                'RoleSessionName': role_session_name
            }
        };
    }
    
    presign(expireIn, signingDate) {
        return this.signature.presign(expireIn, signingDate, this.request);
    }
}

module.exports = AssumeRole;
