var express = require('express');
var querystring  = require('querystring');
const  crypto = require('crypto');
var axios = require('axios');
var router = express.Router();

// geetest 公钥
const CAPTCHA_ID = "647f5ed2ed8acb4be36784e01556bb71";

// geetest 密钥
const CAPTCHA_KEY = "b09a7aafbfd83f73b35a9b530d0337bf";

// geetest 服务地址
const API_SERVER = "http://gcaptcha4.geetest.com";                          

// geetest 验证接口
const API_URL = API_SERVER + "/validate" + "?captcha_id=" + CAPTCHA_ID;


/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index');
});


router.get('/login', function(req, res, next) {
  req.query = querystring.parse(req.url.split('?')[1]);
  // 前端参数
  var lot_number = req.query['lot_number'];
  var captcha_output = req.query['captcha_output'];
  var pass_token = req.query['pass_token'];
  var gen_time = req.query['gen_time'];

  // 生成签名
	// 生成签名使用标准的hmac算法，使用用户当前完成验证的流水号lot_number作为原始消息message，使用客户验证私钥作为key
	// 采用sha256散列算法将message和key进行单向散列生成最终的 “sign_token” 签名
  var sign_token = hmac_sha256_encode(lot_number, CAPTCHA_KEY);

  // 向极验转发前端数据 + “sign_token” 签名
  var datas = {
    'lot_number': lot_number,
    'captcha_output': captcha_output,
    'pass_token': pass_token,
    'gen_time': gen_time,
    'sign_token': sign_token
  };

  // post request 
  // 根据极验返回的用户验证状态, 网站主进行自己的业务逻辑  
  post_form(datas, API_URL).then((result)=>{

    if(result['result'] == 'success'){
      console.log('验证通过');
    }else{
      console.log('验证失败: ' + result['reason']);
    }

  })

  res.send('ok');

});


// 生成签名
function hmac_sha256_encode(value, key){
  var hash = crypto.createHmac("sha256", key)
        .update(value, 'utf8')
        .digest('hex'); 
  return hash;
}


// 发送post请求, 响应json数据如：{"result": "success", "reason": "", "captcha_args": {}}
async function post_form(datas, url){
  var result;
  var options = {
    url: url,
    method: "POST",
    params: datas
  };
  try {
    var result = await axios(options);
  } catch (error) {
    // geetest服务请求异常
    console.log('服务请求异常' + error.code);
    return {'result': 'fail', 'reason': 'server request error'}    
  }

  if(result.status != 200){
    // geetest服务响应异常
    console.log('服务响应异常, statusCode:' + result.status);
    return {'result': 'fail', 'reason': 'server response error'}    
  }
  return result.data;
}


module.exports = router;
