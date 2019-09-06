// mysql.js
var mysql = require('mysql');
// express
const express = require("express");
const app = express();
// body parser
const bodyParser = require('body-parser');
// jwt
const jwt = require("jwt-simple");
// decode jwt
const ExtractJwt = require("passport-jwt").ExtractJwt;
// Strategy
const JwtStrategy = require("passport-jwt").Strategy;
// secret key
const SECRET = "bndxgey34u9034jop"; // Secret key
// Option for jwt Strategy
const jwtOptions = {
   jwtFromRequest: ExtractJwt.fromHeader("authorization"),
   secretOrKey: SECRET
};

const bcrypt = require('bcrypt');

// influxdb-web server-client comunication
const Influx = require('influx');

// http https server
var fs = require('fs');
var http = require('http');
var https = require('https');
var privateKey  = fs.readFileSync('./sslcert/server.key', 'utf8');
var certificate = fs.readFileSync('./sslcert/server.crt', 'utf8');
var credentials = {key: privateKey, cert: certificate};
var httpServer = http.createServer(app);
var httpsServer = https.createServer(credentials, app);

const os = require('os');
// Decode jwt
var jwtDecode = require('jwt-decode');

const influx = new Influx.InfluxDB({
  host: 'localhost:8086',
  username: 'chp-lab',
  password:'atop3352',
  database: 'envdb',
  
  schema: [
    {
      measurement: 'env',
      fields: {
        temp: Influx.FieldType.FLOAT 
      },
      tags: [
        'topic'
      ]
    }
  ]
});


app.use((req, res, next) => {
  const start = Date.now();

  res.on('finish', () => {
    const duration = (Date.now() - start);
    console.log(`Request to ${req.path} took ${duration}ms`);
  });
  return next();
});

const jwtAuth = new JwtStrategy(jwtOptions, (payload, done) => {
	console.log("sub: " + payload.sub);
	
	// Implement Multiple Local User Authentication Strategies in Passport.js
	/*
	Use payload.sub as username to look at databases
	# SELECT username FROM UserInformations WHERE username=payload.sub;
	*/
	
	var username = "\'" + payload.sub + "\'";
	var sql = "SELECT username FROM UserInformations WHERE username= " + username;
	var tag = 'jwtAuth: ';
	
	console.log(sql);
	
	mysql_pool.getConnection(function(err, connection) {
		if (err) {
			connection.release();
			console.log(' Error getting mysql_pool connection: ' + err);
			throw err;
		}
	
	
		connection.query(sql, function(err2, result, fields){
			var resultArray;
			if(err2)
			{
				console.log(' mysql_pool.release()');
				connection.release();
				
				done(null, false);
			}
			console.log(result);
			
			if((result && result.length > 0))
			{
				try{
					resultArray = Object.values(JSON.parse(JSON.stringify(result)));
				}
				catch(e)
				{
					console.log(tag + "unknow error ocurred!");
				}
				if(payload.sub === resultArray[0].username)
				{
					console.log(tag + "Authentication success!");
					done(null, true);
				}
				else
			   {
				   
				   done(null, false);
			   }
			}
			else
			{
				done(null, false);
			}
		
		});
		try
		{
			connection.release();
		}
		catch(errcon)
		{
			console.log("Error on release mysql connection");
		}
	});
});
// passport middle ware auth
const passport = require("passport");
// Enable json body-parser
app.use(bodyParser.json());
// add jwtAuth to passport
passport.use(jwtAuth);
// set public directory
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: false }));

const requireJWTAuth = passport.authenticate("jwt",{	session:false,
														// successRedirect: '/',
														failureRedirect: '/unauthorized'
													});
// port for running server
const HTTP_PORT = process.env.PORT || 81;
const HTTPS_PORT = process.env.PORT || 8443;

// login
const loginMiddleware = (req, res, next) => {
	
	console.log(req.body);
	
	// Use req.body.username and req.body.password to look at databases	
	var username = req.body.username;
	var tmpUser = "\'" + username.replace("\'", "") + "\'";
	var sql = "SELECT password FROM UserInformations WHERE username= " + tmpUser;
	
	console.log(sql);
	
	mysql_pool.getConnection(function(err, connection) {
		if (err) {
			connection.release();
			console.log(' Error getting mysql_pool connection: ' + err);
			throw err;
		}
	
		connection.query(sql, function(err2, result, fields){
			var checkPassword;
			var resultArray;
			
			if(err2)
			{
				console.log('mysql_pool.release()');
				connection.release();
				
				res.json({
					type: false,
					message: 'server_err',
					token: ""
				});
				// throw err;
			}
			
			console.log(result);
			
			
			if((result && result.length > 0))
			{	
				try{
					resultArray = Object.values(JSON.parse(JSON.stringify(result)));
					checkPassword = resultArray[0].password;
					console.log("checkPassword= " + checkPassword);
				}
				catch(e)
				{
					console.log("unknow error ocurred!");
				}
				
				// bcrypt 10 round
				// https://www.devglan.com/online-tools/bcrypt-hash-generator
				// Sample hash source code
				/*
				bcrypt.hash('myPassword', 10, function(err, hash) {
					// Store hash in database
				});
				*/
				
				// https://www.browserling.com/tools/bcrypt
				
				bcrypt.compare(req.body.password, checkPassword, function(err, pass) {
					if(pass) 
					{
						// Passwords match
						console.log("login pass");
						next();
					} 
					else {
						// Passwords don't match
						res.json({
							type: false,
							message: 'login_failed',
							token: ""
						});
						console.log("login failed");
					} 
				});
			}
			else
			{
				console.log("user not found!");
				res.json({
					type: false,
					message: 'user_not_found',
					token: ""
				});
			}	
		});
		try
		{
			connection.release();
		}
		catch(errcon)
		{
			console.log("Error on release mysql connection");
		}
	});
};

// mysql server informations

var db_config = {
	connectionLimit : 100,
	host: "localhost",
	user: "admin",
	password: "0x00ff0000",
	database: "chplab"
};

// var con = mysql.createConnection(db_config);

var mysql_pool  = mysql.createPool(db_config);

// handle login form
// basic flow -> index.html->login.html->homepage.html
app.post("/index", loginMiddleware, (req, res) => {
   const payload = {
      sub: req.body.username,
      iat: new Date().getTime() // iat --> issue at date
   };
   const mytoken = jwt.encode(payload, SECRET);
   //res.send(jwt.encode(payload, SECRET));
   res.json({
                type: true,
                message: 'Authentication successful!',
                token: mytoken
	});
});

// user required information
app.get("/index", requireJWTAuth, (req, res) => {
	console.log("/index passed");
	
    // For support jwt in next release
    // res.send("Authorized");
    // Check token in http header
     res.json({
                type: true,
				message: 'authorized'			
	});
	
});

app.get("/adminlogin", (req, res) => {
     res.sendFile(__dirname + "/" + "adminlogin.html");
	
});

app.get("/administrator", (req, res) => {

	console.log("receive /administrator page req");
	
     res.sendFile(__dirname + "/" + "administrator.html");
	
});

app.post("/dbreq", requireJWTAuth, (req, res) => {
	
});

app.get("/realtime", requireJWTAuth, (req, res) => {
	var decoded = jwtDecode(req.headers.authorization);
	var tmpUsername = `${decoded.sub}`;
	var machineID = `${req.headers.machineid}`;
	var tag = 'realtime';
	// Check permission of user A for access table m
	var sql = `SELECT * FROM Machines WHERE (username='${tmpUsername}' AND machineID='${machineID}')`;
	console.log(sql);
	var jsonMysqlRes;
	
	console.log(tag + tmpUsername + ":" + machineID);
	mysql_pool.getConnection(function(err, connection) {
		if (err) {
			connection.release();
			console.log(' Error getting mysql_pool connection: ' + err);
			res.json({
					type: false,
					message: 'server_error',
					token: ""
			});
			throw err;
		}
		
		connection.query(sql, function(err2, result, fields){
			if(err2)
			{
				console.log(' mysql_pool.release()');
				connection.release();
				
				res.json({
					type: false,
					message: 'server_error',
					token: ""
				});
			}
		
			// Keep user information from mysql
			jsonMysqlRes = JSON.parse(JSON.stringify(result));
			
			console.log(jsonMysqlRes);
			var checkMachineID = jsonMysqlRes[0].machineID;
			
			console.log("checkMachineID= " + checkMachineID);
			if(checkMachineID == machineID)
			{
				console.log("Authorized user req");
				
				
				// Get today data
				var query_cmd = `SELECT *::field FROM "${machineID}" order by desc limit 1`;
				console.log(query_cmd);
						
				// Non blocking function
				influx.query(query_cmd).then(influxResult => {
						var jsonResult = JSON.parse(JSON.stringify(influxResult));
						console.log("########");
						console.log(jsonResult);
						var resultObj = {type:true, username:jsonMysqlRes[0].username, machineID:jsonMysqlRes[0].machineID, machineName:jsonMysqlRes[0].machineName, department:jsonMysqlRes[0].department, results:jsonResult};
						
						res.json(resultObj);
					
					}).catch(err => {
						res.status(500).send(err.stack);
					});
			}
			else
			{
				console.log("Unauthorized user req");
				res.json({type: false, results:'Unauthorized req'});
			}
			
		});
		try
		{
			connection.release();
		}
		catch(errcon)
		{
			console.log("Error on release mysql connection");
		}
	});
	
});

// user required information
app.get("/machine", requireJWTAuth, (req, res) => {
	
	var decoded = jwtDecode(req.headers.authorization);
	var tmpUsername = `'${decoded.sub}'`;
	
	// headers are in lowwer case
	var machineID = `${req.headers.machineid}`;
	var tag = 'machine';
	
	// get datetime from header
	var atdatetime = `${req.headers.atdatetime}`;
	console.log("Start date: " + atdatetime);
	
	var todatetime = `${req.headers.todatetime}`;
	console.log("End date: " + todatetime);
	
	var reqcmd = `${req.headers.reqcmd}`;
	console.log("reqcmd= " + reqcmd);
	
	// Create datetime format for query langauge	
	// Check permission of user A for access table m
	var sql = `SELECT * FROM Machines WHERE (username=${tmpUsername} AND machineID='${machineID}')`;
	console.log(sql);
	var jsonMysqlRes;
	
	mysql_pool.getConnection(function(err, connection) {
		if (err) {
			connection.release();
			console.log(' Error getting mysql_pool connection: ' + err);
			res.json({
					type: false,
					message: 'server_error',
					token: ""
			});
			throw err;
		}
		
		
		connection.query(sql, function(err2, result, fields){
			if(err2)
			{
				console.log(' mysql_pool.release()');
				connection.release();
				
				res.json({
					type: false,
					message: 'server_error',
					token: ""
				});
			}
		
			// Keep user information from mysql
			jsonMysqlRes = JSON.parse(JSON.stringify(result));
			
			console.log(jsonMysqlRes);
			var checkMachineID = jsonMysqlRes[0].machineID;
			
			console.log("checkMachineID= " + checkMachineID);
			if(checkMachineID == machineID)
			{
				console.log("Authorized user req");
				// query data from influxdb
				var d = new Date();
				// Wait->add time to req
				// Header format YYYY-M-D --> Need to slice
				// SQL format YYYY-MM-DD
				var atdateArray = atdatetime.split("-");
				var todateArray = todatetime.split("-");
				
				// splited format: {"YYYY", "M", "D"};
				// var tmp_timeStamp = d.getFullYear().toString() + "-" + ( "0" + (d.getMonth() + 1).toString()).slice(-2) +  "-" + ( "0" + d.getDate().toString()).slice(-2) + 'T00:00:00Z';
				var tmp_timeStamp = atdateArray[0] + "-" + ( "0" + atdateArray[1]).slice(-2) +  "-" + ( "0" + atdateArray[2]).slice(-2);
				var end_timeStamp = todateArray[0] + "-" + ( "0" + todateArray[1]).slice(-2) +  "-" + ( "0" + todateArray[2]).slice(-2);
				
				if(tmp_timeStamp == end_timeStamp)
				{
					console.log("Bad reqcmd");
					reqcmd = "now";
				}

				var query_obj = {tableName: `"${machineID}"`, timeStamp:tmp_timeStamp, endStamp:end_timeStamp, limit: 0};
				
				// Get today data
				// var query_cmd = `SELECT *::field FROM ${query_obj.tableName} WHERE time >= '${query_obj.timeStamp}' AND time <= '${query_obj.endStamp}' limit ${query_obj.limit}`;
				var query_cmd;
				
				if(reqcmd == "now")
				{
					query_cmd = `SELECT *::field FROM ${query_obj.tableName} WHERE time >= '${query_obj.timeStamp}' limit ${query_obj.limit} tz('Asia/Bangkok')`;

				}
				else
				{
					query_cmd = `SELECT *::field FROM ${query_obj.tableName} WHERE time >= '${query_obj.timeStamp}' AND time <='${query_obj.endStamp}' limit ${query_obj.limit} tz('Asia/Bangkok')`;
				}
				console.log(query_cmd);
						
				// Non blocking function
				influx.query(query_cmd).then(influxResult => {
						var jsonResult = JSON.parse(JSON.stringify(influxResult));
						// console.log("!!!!!");
						// console.log(jsonResult);
						var resultObj = {type:true, username:jsonMysqlRes[0].username, machineID:jsonMysqlRes[0].machineID, machineName:jsonMysqlRes[0].machineName, department:jsonMysqlRes[0].department, results:jsonResult};
						
						res.json(resultObj);
					
					}).catch(err => {
						res.status(500).send(err.stack);
					});
			}
			else
			{
				console.log("Unauthorized user req");
				res.json({type: false, results:'Unauthorized req'});
			}
			
		});
		try
		{
			connection.release();
		}
		catch(errcon)
		{
			console.log("Error on release mysql connection");
		}
	});
	
});

app.get('/', function(req, res){
  res.sendFile(__dirname + "/" + "index.html");
});

app.get('/login', function(req, res){
  console.log('req login recv');
  res.sendFile(__dirname + "/" + "login.html");
  
});

app.get('/home', function(req, res){
  res.sendFile(__dirname + "/" + "homepage.html");
});

app.get('/user', function(req, res){
  
  res.sendFile(__dirname + "/user/" + "user.html");
});

app.get('/test', function(req, res){
  
  res.json({type:true, test:"Hello World!"});
});

app.get('/myinform',requireJWTAuth, function (req, res) {
	res.json({
		type:true, 
		message:'Authorized'
	});
});

app.get('/unauthorized', function (req, res) {
	res.json({
        type: false,
		message: 'Unauthorized'			
	});
});

app.get('/list', requireJWTAuth, function (req, res) {
	var decoded = jwtDecode(req.headers.authorization);
	var tmpUsername = decoded.sub;
	var tag = 'list: ';
	// Get table name of user A
	
	var sql = `SELECT * FROM Machines WHERE username='${tmpUsername}'`;
	var jsonMysqlRes;
	
	mysql_pool.getConnection(function(err, connection) {
		if (err) {
			connection.release();
			console.log(' Error getting mysql_pool connection: ' + err);
			res.json({
					type: false,
					message: 'server_error',
					token: ""
			});
			throw err;
		}
		
		
		connection.query(sql, function(err2, result, fields){
			if(err2)
			{
				console.log(' mysql_pool.release()');
				connection.release();
				
				res.json({
					type: false,
					message: 'server_error',
					token: ""
				});
			}
		
			// Keep user information from mysql
			jsonMysqlRes = JSON.parse(JSON.stringify(result));
			console.log(jsonMysqlRes);
			
			res.json({type: true, machines:jsonMysqlRes, detail:tmpUsername});
		});
		try
		{
			connection.release();
		}
		catch(errcon)
		{
			console.log("Error on release mysql connection");
		}
	});
	
	
});
// Method = GET, Authentication header
app.get('/monit', requireJWTAuth, function (req, res) {
	
	// console.log(req.headers.authorization);
	var decoded = jwtDecode(req.headers.authorization);
	var tmpUsername = `'${decoded.sub}'`;
	var tag = 'monit: ';
	// Get table name of user A
	var sql = "SELECT * FROM Machines WHERE username= " + tmpUsername;
	var jsonMysqlRes;
	
	console.log(tag + sql);
	
	// mysql part
	mysql_pool.getConnection(function(err, connection) {
		if (err) {
			connection.release();
			console.log(' Error getting mysql_pool connection: ' + err);
			throw err;
		}
		
		connection.query(sql, function(err2, result, fields){
			if(err2)
			{
				console.log(' mysql_pool.release()');
				connection.release();
				
				res.json({
					type: false,
					message: 'server_error',
					token: ""
				});
			}
		
			// Keep user information from mysql
			jsonMysqlRes = JSON.parse(JSON.stringify(result));
			
			myInflux();
				
			function myInflux()
			{
				var i = 0;
				var __all_results = {};
				var d = new Date();
				var tmp_timeStamp = d.getFullYear().toString() + "-" + ( "0" + (d.getMonth() + 1).toString()).slice(-2) +  "-" + ( "0" + d.getDate().toString()).slice(-2) + 'T00:00:00Z';
				var myJsonKeys = {};
				
				jsonMysqlRes.forEach(function(element){
					// console.log(element);
						
					var query_obj = {tableName: `"${element.machineID}"`, timeStamp:tmp_timeStamp, limit: 0};
					// Get today data
					var query_cmd = `SELECT *::field FROM ${query_obj.tableName} WHERE time > '${query_obj.timeStamp}' limit ${query_obj.limit}`;
					
					
					console.log(query_cmd);
						
					// Non blocking function
					influx.query(query_cmd).then(result => {
						myJsonKeys[i] = `${element.machineName}-${element.machineID}`;
						__all_results[myJsonKeys[i]] = JSON.parse(JSON.stringify(result));
						i = i + 1;
						console.log("Query complete " + i + " time(s)");
						if(i >= jsonMysqlRes.length)
						{
							var resultObj = {type:true, jsonKeys:myJsonKeys, username:jsonMysqlRes[0].username, machineName:jsonMysqlRes[0].machineName, department:jsonMysqlRes[0].department, results:__all_results};
							res.json(resultObj);
						}
					}).catch(err => {
						res.status(500).send(err.stack);
					});
					
				});			
			}
		});
		try
		{
			connection.release();
		}
		catch(errcon)
		{
			console.log("Error on release mysql connection");
		}
	});
});

app.use(function (req, res, next) {
  res.status(404).send("(404) Page not found!");
});

app.use(function (err, req, res, next) {
  console.error(err.stack);
  res.status(500).send('(500) Server error!!');
});
 
 mysql_testConnect();
 // handle mysql connection lost
 function mysql_testConnect() {
	mysql_pool.getConnection(function(err, connection) {
		if (err) 
		{
			connection.release();
			console.log(' Error getting mysql_pool connection: ' + err);
			throw err;
		}
		else
		{
			console.log("mysql connected");
		}
		
	});
	
 }

/**
 * Now, we'll make sure the database exists and boot the app.
 */
influx.getDatabaseNames().then(() => {
	httpServer.listen(HTTP_PORT, () => console.log(`http server listen on port ${HTTP_PORT}`));
	httpsServer.listen(HTTPS_PORT, () => console.log(`https server listen on port ${HTTPS_PORT}`));
	
  }).catch(err => {
    console.error(err);
  });

