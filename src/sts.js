const Signature = require('./signature-v4');

class Sts {

    constructor(access_key_id, secret_access_key) {
        const service = 'sts';
        const region = 'ap-northeast-1';

        this.signature = new Signature(service, region, access_key_id, secret_access_key);

        this.request = {
            method: 'GET',
            protocol: 'https:',
            path: '/',
            headers: {
                host: `${service}.${region}.amazonaws.com`
            },
            hostname: `${service}.${region}.amazonaws.com`,
        };
    }
    
    assumeRole(expireIn, signingDate, role_arn, role_session_name) {
        this.request['query'] = {
            'Action': 'AssumeRole',
            'Version': '2011-06-15',
            'RoleArn': role_arn,
            'RoleSessionName': role_session_name
        };
        return this.signature.presign(expireIn, signingDate, this.request);
    }
}

module.exports = Sts;
