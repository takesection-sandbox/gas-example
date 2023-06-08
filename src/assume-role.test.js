const sha256 = require('crypto-js/sha256');
const hex = require('crypto-js/enc-hex');
const { SignatureV4 } = require('@aws-sdk/signature-v4');
const { Sha256 } = require('@aws-crypto/sha256-js');
const AssumeRole = require('./assume-role');

test ('empty string', () => {
    const empty = hex.stringify(sha256(''));
    expect(empty).toEqual('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test ('presign', () => {
    const signerInit = {
        service: 'sts',
        region: 'ap-northeast-1',
        'sha256': Sha256,
        credentials: {
            accessKeyId: 'foo',
            secretAccessKey: 'bar'
        }
    };

    const signer = new SignatureV4(signerInit);

    const request = {
        'method': 'GET',
        'protocol': 'https:',
        'path': '/',
        'headers': {
            'host': 'sts.ap-northeast-1.amazonaws.com'
        },
        'hostname': 'sts.ap-northeast-1.amazonaws.com',
        'query': {
            'Action': 'AssumeRole',
            'Version': '2011-06-15',
            'RoleArn': 'arn',
            'RoleSessionName': 'session'
        }
    };

    const options = {
        expiresIn: 1800,
        signingDate: new Date('2000-01-01T00:00:00.000Z')
    };

    (async () => {
        const { query } = await signer.presign(request, options);
        console.log(query);
        expect(query['X-Amz-Signature']).toEqual('d742ef81916860bb7c31b796bec1b73aebf85bb31eb695643bbaee0bd4ee6469');
    })();

    const assumeRole = new AssumeRole(signerInit.credentials.accessKeyId, signerInit.credentials.secretAccessKey, request.query.RoleArn, request.query.RoleSessionName);
    const res = assumeRole.presign(options.expiresIn, options.signingDate);
    console.log(res);
    expect(res.query['X-Amz-Signature']).toEqual('d742ef81916860bb7c31b796bec1b73aebf85bb31eb695643bbaee0bd4ee6469');
});
