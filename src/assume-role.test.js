const sha256 = require('crypto-js/sha256');
const hex = require('crypto-js/enc-hex');
const { SignatureV4 } = require('@aws-sdk/signature-v4');
const { Sha256 } = require('@aws-crypto/sha256-js');
const Sts = require('./sts');
const https = require('https');
const xml = require('fast-xml-parser');

test ('empty string', () => {
    const empty = hex.stringify(sha256(''));
    expect(empty).toEqual('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test ('assume role', () => {
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

    const sts = new Sts(signerInit.credentials.accessKeyId, signerInit.credentials.secretAccessKey);
    const res = sts.assumeRole(options.expiresIn, options.signingDate, request.query.RoleArn, request.query.RoleSessionName);
    console.log(res);
    expect(res.query['X-Amz-Signature']).toEqual('d742ef81916860bb7c31b796bec1b73aebf85bb31eb695643bbaee0bd4ee6469');
});

test.skip ('assumeRole', () => {
    const accessKeyId = process.env['AWS_ACCESS_KEY_ID'];
    const secretAccessKey = process.env['AWS_SECRET_ACCESS_KEY'];
    const roleArn = process.env['ROLE_ARN'];
    const sts = new Sts(accessKeyId, secretAccessKey);
    const signed = sts.assumeRole(1800, new Date(), roleArn, 'test');
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

    var responseText = '';
    https.get(url + params, (res) => {
        expect(res.statusCode).toEqual(200);
        res.on('data', (data) => {
            responseText = data.toString('utf8');
            responseJson = new xml.XMLParser().parse(responseText);
            process.stdout.write(JSON.stringify(responseJson) + '\n\n');

            const accessKeyId = responseJson['AssumeRoleResponse']['AssumeRoleResult']['Credentials']['AccessKeyId'];
            const secretAccessKey = responseJson['AssumeRoleResponse']['AssumeRoleResult']['Credentials']['SecretAccessKey'];
            const sessionToken = responseJson['AssumeRoleResponse']['AssumeRoleResult']['Credentials']['SessionToken'];
            process.stdout.write(`AWS_ACCESS_KEY_ID=${accessKeyId}\n`);
            process.stdout.write(`AWS_SECRET_ACCESS_KEY=${secretAccessKey}\n`);
            process.stdout.write(`SESSION_TOKEN=${sessionToken}\n`);
        }).on('error', (e) => {
            process.stderr.write(e);
        })
    });
});
