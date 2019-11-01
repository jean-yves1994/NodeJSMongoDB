var mongodb = require('mongodb');
var ObjectID = mongodb.ObjectID;

var crypto = require('crypto');
var express = require('express');
var bodyParser = require('body-parser');


//PASSWORD UTILS
//CREATE FUNCTION TO RANDOM SALT
var genRandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
    .toString('hex')
    .slice(0,length);
};

var sha512 = function(password,salt){
    var hash = crypto.createHmac('sha512',salt);
    hash.update(password);
    var value = hash.digest('hex');
    return{
        salt:salt,
        passwordHash:value
    };
};

function saltHashPassword(userPassword){
    var salt = genRandomString(16); //Create 16 random characters
    var passwordData = sha512(userPassword,salt);
    return passwordData;
}

function checkHashPassword(userPassword,salt){
    var passwordData = sha512(userPassword,salt);
    return passwordData;
}

//Create Express Services

var app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

//Create MongoDB Client
var MongoClient = mongodb.MongoClient;

//Coonection URL
//var url = 'mongodb://localhost:27017' //Defaul port 
var url = 'mongodb+srv://kingbeats:root@mynodejsapi-htzwm.mongodb.net/test?retryWrites=true&w=majority';


MongoClient.connect(url,{useNewUrlParser: true},function(err,client){
    if(err)
    console.log('Unable to connect to mongoDB server', err);
    else{

        //Register
        app.post('/register',(request,response,next)=>{
            var post_data = request.body;
            
            var plaint_password = post_data.password;
            var hash_data = saltHashPassword(plaint_password);

            var password = hash_data.passwordHash; //Save password hash
            var salt = hash_data.salt; //Save salt

            var name = post_data.name;
            var email = post_data.email;
            var phone = post_data.phone;

            var insertJson={
                'email':email,
                'password':password,
                'salt':salt,
                'phone': phone,
                'name': name,
                'isMobileLoggedIn':false
            };
            var db = client.db('secureid');

            //Check existed email
            db.collection('user')
            .find({'email':email}).count(function(err,number){
                if(number !=0)
                {
                    response.json('Email already exists');
                    console.log('Email already exists');
                }
                else{
                    db.collection('user')
                    .insertOne(insertJson,function(error,res){
                        response.json('Registration success');
                    console.log('Registration success');
                    })
                }
            })
        });

        app.post('/login',(request,response,next)=>{
            var post_data = request.body;
            
            var email = post_data.email;
            var userPassword = post_data.password;
            var device = post_data.device;

            var db = client.db('secureid');

            //Check existed email
            db.collection('user')
            .find({'email':email}).count(function(err,number){
                if(number ==0)
                {
                    response.json('Email does not exist');
                    console.log('Email does not exist');
                }
                else{
                    db.collection('user')
                    .findOne({'email':email},function(err,user){
                        var salt = user.salt; //Get salt from user
                        var hashed_password = checkHashPassword(userPassword,salt).passwordHash;
                        var encrypted_password = user.password;
                        if(hashed_password ==encrypted_password)
                        {
							//Check if user is Mobile logged in
                            response.json(email);
                            console.log('Login success');
                            if(device === "Mobile"){
                                user.isMobileLoggedIn = true;
                                db.collection('user').update({email:email},user,function(err,updatedUser){
                                    if(err){
                                        console.log(err);
                                    }else{
                                        console.log("success");
            
                                    }
                                })
                            }
                        }
                        else{
                            response.json('Wrong password');
                            console.log('Wrong password'); 
                        }
                    })
                }
            })
        });

        app.get('/logout',function(req,res){
            var email = req.body.email;
            var device = req.body.device;
            var db = client.db('secureid');

            db.collection('user').findOne({email:email},function(err,user){
                if(err){
                    console.log(err);
                }else{
                    if(device === "Mobile"){
                        user.isMobileLoggedIn = false;
                        db.collection('user').update({email:email},user,function(err,updatedUser){
                            if(err){
                                console.log(err);
                            }else{
                                console.log("success");
                                res.json("You are logged out");
                            }
                        })
                    }
                }
            })
        })
        //Start web server
        app.listen(3000,()=>{
            console.log('Connected to MongoDB server, WebService running on port 3000');
        })
    }
});