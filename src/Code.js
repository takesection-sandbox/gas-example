const Sts = require('./sts');
const S3 = require('./s3');
const xmlparser = require('fast-xml-parser');

global.putObject = () => {
    const credential = global.assumeRole();
    
    const properties = PropertiesService.getScriptProperties();
    const bucketName = properties.getProperty('BUCKET_NAME');
    const key = '/test.json';
    const contentType = 'application/json';
    const region = 'ap-northeast-3';

    const content = {
        message: 'Hello world'
    };
    const res = global.S3.putObject(credential.AWS_ACCESS_KEY_ID
        ,credential.AWS_SECRET_ACCESS_KEY
        ,region
        ,bucketName
        ,key
        ,contentType 
        ,JSON.stringify(content)
        ,credential.SESSION_TOKEN);

    Logger.log(res);
    return res; 
}

global.assumeRole = () => {
    const properties = PropertiesService.getScriptProperties();
    const access_key_id = properties.getProperty('ACCESS_KEY_ID');
    const secret_access_key = properties.getProperty('SECRET_ACCESS_KEY');
    const region = 'ap-northeast-1';
    const role_arn = properties.getProperty('ROLE_ARN');
    const role_session_name = 'test';

    const res = global.Sts.assumeRole(access_key_id, secret_access_key, region, role_arn, role_session_name);
    Logger.log(res);

    return res;
};

global.Signature = require('./signature-v4');

global.Sts = {
    assumeRole: (access_key_id, secret_access_key, region, role_arn, role_session_name) => {
        const req = new Sts(access_key_id, secret_access_key, region).assumeRole(1800, new Date(), role_arn, role_session_name);
        
        const query = Object.entries(req.query).reduce((acc, [key, value]) => {
            acc.push(key + '=' + value);
            return acc;
        }, []).join('&');
        const url = `${req.protocol}//${req.hostname}${req.path}?${query}`;

        const response = UrlFetchApp.fetch(url);
       
        const text = response.getContentText();
        const json = new xmlparser.XMLParser().parse(text);

        const credential = json['AssumeRoleResponse']['AssumeRoleResult']['Credentials'];
        const res = {
            'AWS_ACCESS_KEY_ID': credential['AccessKeyId'],
            'AWS_SECRET_ACCESS_KEY': credential['SecretAccessKey'],
            'SESSION_TOKEN': credential['SessionToken']
        };
        return res;
    }
};

global.S3 = {
    putObject: (access_key_id, secret_access_key, region, bucket_name, key, contentType, payload, session_token) => {
        const s3 = new S3(access_key_id, secret_access_key, region, session_token);
        const req = s3.putObject(new Date(), bucket_name, key, contentType);
        const headers = Object.entries(req.headers)
            .filter(([key, value]) => key.toLowerCase() !== 'host')
            .reduce((acc, [key, value]) => {
            acc[key] = value;
            return acc
        }, {});
        const url = `${req.protocol}//${req.hostname}${req.path}`;
        const options = {
            'method': 'put',
            'payload': payload,
            'headers': headers 
        };
        return UrlFetchApp.fetch(url, options);
    }
};
