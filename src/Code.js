const Sts = require('./sts');
const S3 = require('./s3');

const xmlparser = require('fast-xml-parser');

global.assumeRole = () => {
    const properties = PropertiesService.getScriptProperties();
    const access_key_id = properties.getProperty('ACCESS_KEY_ID');
    const secret_access_key = properties.getProperty('SECRET_ACCESS_KEY');
    const role_arn = properties.getProperty('ROLE_ARN');
    const role_session_name = 'test';
    
    const req = new Sts(access_key_id, secret_access_key).assumeRole(1800, new Date(), role_arn, role_session_name);
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
    Logger.log(res);
    return res;
};

global.putObject = () => {
    const credential = global.assumeRole();
    
    const properties = PropertiesService.getScriptProperties();
    const bucketName = properties.getProperty('BUCKET_NAME');

    const s3 = new S3(credential.AWS_ACCESS_KEY_ID, credential.AWS_SECRET_ACCESS_KEY, credential.SESSION_TOKEN);
    const contentType = 'application/json';
    const content = {
        message: 'Hello world'
    };
    const req = s3.putObject(new Date(), bucketName, '/test.json', contentType);

    Logger.log(req);

    const headers = Object.entries(req.headers)
        .filter(([key, value]) => key.toLowerCase() !== 'host')
        .reduce((acc, [key, value]) => {
        acc[key] = value;
        return acc
    }, {});
    Logger.log(headers);

    const url = `${req.protocol}//${req.hostname}${req.path}`;
    const options = {
        'method': 'put',
        'payload': JSON.stringify(content),
        'headers': headers 
    };
    
    const res = UrlFetchApp.fetch(url, options);
    Logger.log(res); 
}
