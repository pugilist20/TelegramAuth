
import crypto from 'crypto';


const botToken = '7136595610:AAHAlC_spefMkCdgkD5k9ekDGmfTCJo2UO4';


const initData = {
    id: '123456',
    first_name: 'Ivan',
    username: 'ivan123',
    auth_date: String(Math.floor(Date.now() / 1000)),
};


const keys = Object.keys(initData).sort();
const dataCheckString = keys.map(k => `${k}=${initData[k]}`).join('\n');


const secretKey = crypto.createHash('sha256')
    .update(botToken, 'utf8')
    .digest();


const hmac = crypto.createHmac('sha256', secretKey)
    .update(dataCheckString, 'utf8')
    .digest('hex');

console.log('data_check_string:\n' + dataCheckString);
console.log('\ngenerated hash:', hmac);
console.log('\nИспользуйте в URL:\n' +
    `?${dataCheckString}&hash=${hmac}`);
