const sha256 = require('crypto-js/sha256');
const hex = require('crypto-js/enc-hex');
const { SignatureV4 } = require('@aws-sdk/signature-v4');
const { Sha256 } = require('@aws-crypto/sha256-js');
const AssumeRole = require('./assume-role');
const https = require('https');
const xml = require('fast-xml-parser');

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

test ('assumeRole', () => {
    const accessKeyId = process.env['AWS_ACCESS_KEY_ID'];
    const secretAccessKey = process.env['AWS_SECRET_ACCESS_KEY'];
    const roleArn = process.env['ROLE_ARN'];
    const assumeRole = new AssumeRole(accessKeyId, secretAccessKey, roleArn, 'test');
    const signed = assumeRole.presign(1800, new Date());
    const url = `${signed.protocol}//${signed.hostname}${signed.path}?`;
    const params = Object.entries(signed.query).reduce((acc, [key, value]) => {
        if (acc) {
            acc += '&' + key + '=' + value;
        } else {
            acc = key + '=' + value;
        }
        return acc;
    }, '');

    console.log(url + params);

    (async () => {
        var responseText = '';
        await https.get(url + params, (res) => {
            expect(res.statusCode).toEqual(200);
            res.on('data', (data) => {
                responseText = data.toString('utf8');
                process.stdout.write(JSON.stringify(new xml.XMLParser().parse(responseText)));
            }).on('error', (e) => {
                process.stderr.write(e);
            })
        });
    })();
});
