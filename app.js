const express = require("express")
const path = require("path")
const session = require("express-session")
const passport = require("passport")
const LocalStrategy = require("passport-local").Strategy
const mongoose = require("mongoose")
const Schema = mongoose.Schema

const mongoDB = "mongodb+srv://user:user@cluster0.19mwv.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"
mongoose.connect(mongoDB, { useUnifiedTopology: true, useNewUrlParser: true })
const db = mongoose.connection
db.on("error", console.error.bind(console, "MongoDB Error"))

const User = mongoose.model(
    "User",
    new Schema({
        username: { type: String, required: true },
        password: { type: String, required: true },
    })
)

const app = express()
app.set("views", __dirname + "/views")
app.set("view engine", "ejs")

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }))

// Try to find the user in the MongoDB when using passport.authenticate()
passport.use(
    new LocalStrategy((username, password, done) => {
        User.findOne({ username: username }, (err, user) => {
            if (err) {
                return done(err)
            }
            if (!user) {
                return done(null, false, { message: "Incorrect username" })
            }
            if (user.password !== password) {
                return done(null, false, { message: "Incorrect password" })
            }
            return done(null, user)
        })
    })
)

passport.serializeUser(function (user, done) {
    done(null, user.id)
})

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user)
    })
})

app.use(passport.initialize())
app.use(passport.session())
app.use(express.urlencoded({ extended: false }))

app.use(function (req, res, next) {
    res.locals.user = req.user
    next()
})

app.get("/", (req, res) => {
    res.render("index")
})

app.get("/sign-up", (req, res) => {
    res.render("sign-up-form")
})

app.post("/sign-up", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password,
    }).save((err) => {
        if (err) {
            return next(err)
        }

        res.redirect("/")
    })
})

app.post(
    "/log-in",
    passport.authenticate("local", {
        successRedirect: "/",
        failureRedirect: "/",
    })
)

app.get("/log-out", (req, res) => {
    req.logout()
    res.redirect("/")
})

app.listen(3000, () => {
    console.log("App listening on port 3000!")
})
