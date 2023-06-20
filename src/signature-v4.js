const sha256 = require('crypto-js/sha256');
const hmac = require('crypto-js/hmac-sha256');
const hex = require('crypto-js/enc-hex');

class Signature {
    
    constructor(service, region, access_key_id, secret_access_key) {
        this.service = service;
        this.region = region;
        this.access_key_id = access_key_id;
        this.secret_access_key = secret_access_key;
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

    presign(expireIn, signingDate, request) {
        const dateStringFull = this.dateStringFull(signingDate);
        const dateStringShort = this.dateStringShort(signingDate);

        const headers = Object.keys(request.headers).sort((a, b) => a < b ? -1 : 1).reduce((acc, k) => {
            acc += k.toLowerCase() + ':' + request.headers[k] + '\n';
            return acc;
        }, '');

        const algorithm = 'AWS4-HMAC-SHA256';
        const scope = dateStringShort + '/' + this.region + '/' + this.service + '/aws4_request';
        
        request.query['X-Amz-Algorithm'] = algorithm;
        request.query['X-Amz-Credential'] = `${this.access_key_id}/${scope}`;
        request.query['X-Amz-Date'] = dateStringFull;
        request.query['X-Amz-Expires'] = expireIn.toString();

        request.query['X-Amz-SignedHeaders'] = 'host';

        const query = Object.entries(request.query).sort((a, b) => a[0] < b[0] ? -1 : 1).reduce((acc, [key, value]) => {
            if (acc) {
                acc += '&' + key + '=' + this.fixedEncodeURIComponent(value);
            } else {
                acc = key + '=' + this.fixedEncodeURIComponent(value);
            }
            return acc;
        }, '');

        const canonicalString = request.method + '\n'
            + request.path + '\n'
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
        request.query['X-Amz-Signature'] = hex.stringify(hmac(stringToSign, key));

        return request;
    }
}

module.exports = Signature;
