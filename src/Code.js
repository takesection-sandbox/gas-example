const Sts = require('./sts');
const S3 = require('./s3');
const xmlparser = require('fast-xml-parser');

global.doGet = () => {
    const properties = PropertiesService.getScriptProperties();
    const role_arn = properties.getProperty('ROLE_ARN'); 
    const role_session_name = 'app1';
    
    const oidcToken = ScriptApp.getIdentityToken();
    Logger.log(oidcToken);

    const token = encodeURIComponent(oidcToken);
    const formData = `Action=AssumeRoleWithWebIdentity&RoleSessionName=${role_session_name}&RoleArn=${role_arn}&WebIdentityToken=${token}&Version=2011-06-15`;
    const res = UrlFetchApp.fetch("https://sts.amazonaws.com/", {
        'method': 'post',
        "payload": formData
    });

    const xml = res.getContentText();
    const json = new xmlparser.XMLParser().parse(xml);
    const text = JSON.stringify(json);
    Logger.log(text);

    const credentials = json['AssumeRoleWithWebIdentityResponse']['AssumeRoleWithWebIdentityResult']['Credentials'];
    const access_key_id = credentials['AccessKeyId'];
    const secret_access_key = credentials['SecretAccessKey'];
    const session_token = credentials['SessionToken'];
    const temporary_security_credentials = {
        "ACCESS_KEY_ID": access_key_id,
        "SECRET_ACCESS_KEY": secret_access_key,
        "SESSION_TOKE": session_token
    };

    return ContentService.createTextOutput(JSON.stringify(temporary_security_credentials)).setMimeType(ContentService.MimeType.JSON);
};

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
};

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
