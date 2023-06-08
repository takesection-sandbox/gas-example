const sha256 = require('crypto-js/sha256');
const hmac = require('crypto-js/hmac-sha256');
const hex = require('crypto-js/enc-hex');

class AssumeRole {

    constructor(access_key_id, secret_access_key, role_arn, role_session_name) {
        this.access_key_id = access_key_id;
        this.secret_access_key = secret_access_key;
        this.role_arn = role_arn;
        this.role_session_name = role_session_name;

        this.service = 'sts';
        this.region = 'ap-northeast-1';

        this.request = {
            method: 'GET',
            protocol: 'https:',
            path: '/',
            headers: {
                host: 'sts.ap-northeast-1.amazonaws.com'
            },
            hostname: 'sts.ap-northeast-1.amazonaws.com',
            query: {
                'Action': 'AssumeRole',
                'Version': '2011-06-15',
                'RoleArn': role_arn,
                'RoleSessionName': this.role_session_name
            }
        };
    }
    
    addZero(s) {
        return (Number(s) < 10 ? '0' : '') + String(s);
    }

    dateStringFull(d) {
        return String(d.getUTCFullYear()) + this.addZero(d.getUTCMonth()+1) + this.addZero(d.getUTCDate()) + "T" + this.addZero(d.getUTCHours()) + this.addZero(d.getUTCMinutes()) + this.addZero(d.getUTCSeconds()) + 'Z';
    }
   
    dateStringShort(d) {
        return String(d.getUTCFullYear()) + this.addZero(d.getUTCMonth()+1) + this.addZero(d.getUTCDate());
    }
    
    getSignatureKey(key, dateStamp, regionName, serviceName) {
        var kDate = hmac(dateStamp, "AWS4" + key);
        var kRegion = hmac(regionName, kDate);
        var kService = hmac(serviceName, kRegion);
        var kSigning = hmac("aws4_request", kService);

        return kSigning;
    }
    
    fixedEncodeURIComponent(str) {
        return encodeURIComponent(str).replace(/[!'()*]/g, function(c) {
          return '%' + c.charCodeAt(0).toString(16).toUpperCase();
        });
    }

    presign(expireIn, signingDate) {
        const dateStringFull = this.dateStringFull(signingDate);
        const dateStringShort = this.dateStringShort(signingDate);

        const headers = Object.keys(this.request.headers).sort((a, b) => a < b ? -1 : 1).reduce((acc, k) => {
            acc += k.toLowerCase() + ':' + this.request.headers[k] + '\n';
            return acc;
        }, '');

        const algorithm = 'AWS4-HMAC-SHA256';
        const scope = dateStringShort + '/' + this.region + '/' + this.service + '/aws4_request';
        
        this.request.query['X-Amz-Algorithm'] = algorithm;
        this.request.query['X-Amz-Credential'] = `${this.access_key_id}/${scope}`;
        this.request.query['X-Amz-Date'] = dateStringFull;
        this.request.query['X-Amz-Expires'] = expireIn.toString();

        this.request.query['X-Amz-SignedHeaders'] = 'host';

        const query = Object.entries(this.request.query).sort((a, b) => a[0] < b[0] ? -1 : 1).reduce((acc, [key, value]) => {
            if (acc) {
                acc += '&' + key + '=' + this.fixedEncodeURIComponent(value);
            } else {
                acc = key + '=' + this.fixedEncodeURIComponent(value);
            }
            return acc;
        }, '');

        const canonicalString = this.request.method + '\n'
            + this.request.path + '\n'
            + query + '\n'
            + headers + '\n'
            + 'host' + '\n'
            + hex.stringify(sha256(''));
       
        const canonHash = hex.stringify(sha256(canonicalString));

        const stringToSign = algorithm + '\n'
            + dateStringFull + '\n'
            + scope + '\n'
            + canonHash;
       
        const key = this.getSignatureKey(this.secret_access_key, dateStringShort, this.region, this.service);
        this.request.query['X-Amz-Signature'] = hex.stringify(hmac(stringToSign, key));

        return this.request;
    }
}

module.exports = AssumeRole;
