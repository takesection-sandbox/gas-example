const AssumeRole = require('./assume-role');
const xmlparser = require('fast-xml-parser');

global.assumeRole = () => {
    const properties = PropertiesService.getScriptProperties();
    const access_key_id = properties.getProperty('ACCESS_KEY_ID');
    const secret_access_key = properties.getProperty('SECRET_ACCESS_KEY');
    const role_arn = properties.getProperty('ROLE_ARN');
    const role_session_name = 'test';
    
    const req = new AssumeRole(access_key_id, secret_access_key, role_arn, role_session_name).presign(1800, new Date());
    const query = Object.entries(req.query).reduce((acc, [key, value]) => {
        acc.push(key + '=' + value);
        return acc;
    }, []).join('&');
    const url = `${req.protocol}//${req.hostname}${req.path}?${query}`;

    const response = UrlFetchApp.fetch(url);
    const text = response.getContentText();
    const json = new xmlparser.XMLParser().parse(text);

    Logger.log(json);
};
