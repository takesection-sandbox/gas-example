const { SignatureV4 } = require('@aws-sdk/signature-v4');
const { Sha256 } = require('@aws-crypto/sha256-js');
const Signature = require('./signature-v4');
const https = require('https');
const S3 = require('./s3');
const { sign } = require('crypto');

test ('sign', async () => {
    const signerInit = {
        service: 's3',
        region: 'ap-northeast-3',
        'sha256': Sha256,
        credentials: {
            accessKeyId: 'foo',
            secretAccessKey: 'bar'
        }
    };

    const signer = new SignatureV4(signerInit);
    const bucketName = 'mybucket';
    const contentType = 'application/json';

    const request = {
        'method': 'PUT',
        'protocol': 'https:',
        'path': '/my.json',
        'headers': {
            'host': `${bucketName}.s3.ap-northeast-3.amazonaws.com`,
            'Content-Type': contentType,
            'X-Amz-Content-Sha256': 'UNSIGNED-PAYLOAD',
            'X-Amz-Security-Token': 'baz'
        },
        'hostname': `${bucketName}.s3.ap-northeast-3.amazonaws.com`
    };

    const signingDate = new Date('2000-01-01T00:00:00.000Z');
    const { headers } = await signer.sign(
        request,
        { 'signingDate': signingDate }
    );
    
    console.log(headers);

    const s3 = new S3(signerInit.credentials.accessKeyId, signerInit.credentials.secretAccessKey, signerInit.region, 'baz');
    const res = s3.putObject(signingDate, bucketName, request.path, contentType, 0);

    console.log(res.headers);

    expect(res.headers['Authorization']).toEqual(headers['authorization']);
});

test.skip ('put-object', () => {
    const accessKeyId = process.env['AWS_ACCESS_KEY_ID'];
    const secretAccessKey = process.env['AWS_SECRET_ACCESS_KEY'];
    const securityToken = process.env['SESSION_TOKEN'];

    const bucketName = process.env['BUCKET_NAME'];

    const signature = new Signature('s3', 'ap-northeast-3', accessKeyId, secretAccessKey);

    const request = {
        'method': 'PUT',
        'protocol': 'https:',
        'path': '/test.json',
        'headers': {
            'host': `${bucketName}.s3.ap-northeast-3.amazonaws.com`,
            'Content-Type': 'application/json',
            'X-Amz-Content-Sha256': 'UNSIGNED-PAYLOAD',
            'X-Amz-Security-Token': securityToken
        },
        'hostname': `${bucketName}.s3.ap-northeast-3.amazonaws.com`
    };

    const signedRequest = signature.sign(new Date(), request);
    
    const payload = JSON.stringify(signedRequest);
    signedRequest.headers['Content-Length'] = payload.length;

    const url = `${request.protocol}//${request.hostname}${request.path}`;
    const options = {
        method: 'PUT',
        'headers': signedRequest.headers
    }
    
    console.log(url);

    const req = https.request(url, options, res => {
        res.on('data', data => {
            process.stdout.write(JSON.stringify(data.toString('utf8')));
        }).on('error', e => {
            process.stderr.write(e);
        })
    });
    req.write(JSON.stringify(bucketName));
    req.end();
});
