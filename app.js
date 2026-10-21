require("dotenv").config()
const cors = require('cors');
const express = require("express")
const { Pool } = require("pg")
const val = require("validator")
const bc = require("bcrypt")
const jwt = require("jsonwebtoken")

const app = express()

app.use(express.json())

app.use(cors())

app.use(express.urlencoded())


app.use((req, res, next) => {
    console.log(req.url)
    next()
})

const con = new Pool({
    connectionString: process.env.databaseUrl
})

function auth(req, res) {
    const header = req.headers.authorization
    const token = header && header.split(" ")[1]

    try {
        const user = jwt.verify(token, process.env.secret)
        console.log("Authunticated : ", user)
        return user
    } catch (error) {
        console.log("unauthorized : ", error)
        throw new Error("unauthorized");
    }
}

async function testDatabaseConection() {
    try {
        const result = await con.query("SELECT NOW()")
        console.log(result.rows)
        console.log("the conection is good")
    } catch (error) {
        console.log("there is an error in the conection")
    }
}

function checkTransactionObject(ob, fields) {
    const { transaction_id, transaction_type, amount, source, transaction_date } = ob
    fields.forEach(field => {

        if (field === "transaction_id") {
            if (typeof (transaction_id) !== "number" || transaction_id <= 0) {
                throw new Error("Transaction_id is required and higher then 0");
            }
        }
        else if (field === "transaction_type") {
            if (!["income", "outcome"].includes(transaction_type)) {
                throw new Error("Invalid transaction type");
            }
        }
        else if (field === "amount") {
            if (typeof (amount) !== "number" || amount <= 0) {
                throw new Error("Amount must be a positive number and higher then 0");
            }
        }
        else if (field === "source") {
            if (typeof (source) !== "string" || source === "") {
                throw new Error("Source must be string and not empty");
            }
        }
        else {
            throw new Error(`Unknown field: ${field}`);
        }
    });

    return ob
}

function checkUserBody(ob, fields) {
    const { nickname, username, email, password } = ob
    fields.forEach(field => {
        if (field === "nickname") {
            if (typeof (nickname) !== "string" || nickname === "") {
                throw new Error("Nickname must be string and not empty string");
            }
        }
        else if (field === "username") {
            if (typeof (username) !== "string" || username === "") {
                throw new Error("Username must be string and not empty string");
            }
        }
        else if (field === "email") {
            if (typeof (email) !== "string" || email === "") {
                throw new Error("Email must be string and not empty string");
            }
            if (!val.isEmail(email)) {
                throw new Error("Email format Incorrect");
            }
        }
        else if (field === "password") {
            if (typeof (password) !== "string" || password === "") {
                throw new Error("Password must be string and not empty string");
            }

            let passwordRequirements = {
                minLength: 4,                  // الحد الأدنى للطول هو 8 محارف
                minLowercase: 0,               // محرف صغير واحد على الأقل (a-z)
                minUppercase: 0,               // محرف كبير واحد على الأقل (A-Z)
                minNumbers: 1,                 // رقم واحد على الأقل (0-9)
                minSymbols: 0,                 // رمز خاص واحد على الأقل (مثل @, #, $, إلخ)
                returnScore: false,            // إرجاع قيمة منطقية (Boolean) وليس نتيجة رقمية
                pointsPerUnique: 1,            // النقاط الممنوحة لكل محرف فريد
                pointsPerRepeat: 0.5,          // النقاط الممنوحة عند تكرار المحارف
                pointsForContainingLower: 10,  // نقاط إضافية لوجود محارف صغيرة
                pointsForContainingUpper: 10,  // نقاط إضافية لوجود محارف كبيرة
                pointsForContainingNumber: 10, // نقاط إضافية لوجود أرقام
                pointsForContainingSymbol: 10  // نقاط إضافية لوجود رموز
            }
            if (!val.isStrongPassword(password, passwordRequirements)) {
                throw new Error(`Enter stronger password`);
            }
        }
        else {
            throw new Error(`Unknown field: ${field}`);
        }
    })
    return ob
}

app.get("/", (req, res) => {
    res.status(200).json({ "message": "welcome to my api" })
})

app.post("/create-user", async (req, res) => {
    console.log(req.body)
    let user_info = {}

    try {
        user_info = checkUserBody(req.body, ["nickname", "username", "email", "password"])
    } catch (error) {
        console.log("Error in request body : ", error.message)
        res.status(400).send({ message: error.message })
        return
    }

    let { nickname, username, email, password } = user_info

    try {
        password = await bc.hash(password, 5)
    } catch (error) {
        console.log("Error from the server that the hashing faild exists: ", error)
        res.status(500).send({ message: "Error from the server " })
        return
    }

    try {
        const selectq = `SELECT * FROM users_data 
                        WHERE username = $1 OR email = $2
        `
        let values = [username, email]
        const selectResult = await con.query(selectq, values)
        if (selectResult.rowCount > 0) {
            console.log("The username or email already exists")
            res.status(409).send({ message: "The username or email already exists" })
            return
        }
    } catch (error) {
        console.log("Error frome the Database while checking if the user already exists: ", error)
        res.status(500).send({ message: "Error frome the Database while checking if the user already exists: " })
        return
    }

    try {
        const insertq = `INSERT INTO users_data (username , email , password , nickname) 
        VALUES ($1,$2,$3,$4)
        RETURNING id , username, email, nickname
        `
        let values = [username, email, password, nickname]
        const addingResult = await con.query(insertq, values)
        try {
            const newUserId = addingResult.rows[0].id
            let token = jwt.sign({ id: newUserId, roll: "normalUser" }, process.env.secret, { expiresIn: "1h" })
            console.log({
                "what's added": addingResult.rows,
                "JWT": token
            })
            res.status(201).send({
                "what's added": addingResult.rows,
                "JWT": token
            })
            return
        } catch (error) {
            console.log("Error frome the Database while making the JWT: ", error)
            res.status(500).send({ message: "Error frome the Database while adding the user: " })
            return
        }
    } catch (error) {
        console.log("Error frome the Database while adding the user: ", error)
        res.status(500).send({ message: "Error frome the Database while adding the user: " })
        return
    }

})

app.post("/log-in", async (req, res) => {
    console.log(req.body)

    let user_info = {}
    let id
    try {
        user_info = checkUserBody(req.body, ["username", "password"])
    } catch (error) {
        console.log("Error in request body : ", error.message)
        res.status(400).send({ message: error.message })
        return
    }

    let { username, password } = user_info

    try {
        const usernameCheckq = `SELECT * FROM users_data WHERE username = $1`
        const usernameCheckResult = await con.query(usernameCheckq, [username])
        if (usernameCheckResult.rowCount <= 0) {
            console.log("the username Incorrect")
            res.status(401).send({ message: "the username or password is Incorrect" })
            return
        }
        id = usernameCheckResult.rows[0].id
    } catch (error) {
        console.log("Error frome the Database while checking the user existing: ", error)
        res.status(500).send({ message: "Error frome the Database while checking the user existing" })
        return
    }

    try {
        const passwordnameCheckq = `SELECT password FROM users_data WHERE username = $1`
        const passwordCheckResult = await con.query(passwordnameCheckq, [username])
        const compareing = await bc.compare(password, passwordCheckResult.rows[0].password)
        if (passwordCheckResult.rowCount <= 0 || compareing === false) {
            console.log("the password Incorrect")
            res.status(401).send({ message: "the username or password is Incorrect" })
            return
        }
    } catch (error) {
        console.log("Error frome the Database while checking the password correction: ", error)
        res.status(500).send({ message: "Error frome the Database while checking the password correction" })
        return
    }

    try {
        let token = jwt.sign({ "id": id, "roll": "normalUser" }, process.env.secret, { expiresIn: "1h" })
        console.log({
            "message": "welcome to your Budget Tracker",
            "JWT": token
        })
        res.status(201).send({
            "message": "welcome to your Budget Tracker",
            "JWT": token
        })
        return
    } catch (error) {
        console.log("Error frome the Database while making the JWT: ", error)
        res.status(500).send({ message: "Error frome the Database while adding the user: " })
        return
    }

})

app.get("/all-transactions", async (req, res) => {
    console.log("req.header = ", req.headers)
    let user
    try {
        user = auth(req, res)
    } catch (error) {
        res.status(401).send({ message: error.message })
        return
    }

    try {
        const selectResult = await con.query("SELECT * FROM transactions WHERE user_id = $1 ORDER BY transaction_id", [user.id])
        res.status(200).send(selectResult.rows)
    } catch (error) {
        console.log("error from database while trying to select the transactions : ", error)
        res.status(500).send({ "message": "error from database" })
    }
})

app.post("/create-transaction", async (req, res) => {
    console.log(req.body)
    let user
    try {
        user = auth(req, res)
    } catch (error) {
        res.status(401).send({ message: error.message })
        return
    }

    let transaction_info = {}

    try {
        transaction_info = checkTransactionObject(req.body, ["transaction_type", "amount", "source"])
    } catch (error) {
        res.status(400).send({ message: error.message })
        return
    }
    const { transaction_type, amount, source, transaction_date } = transaction_info

    let q = `INSERT INTO transactions (user_id , transaction_type , amount , source , transaction_date) 
        VALUES ($1,$2,$3,$4,$5)
        RETURNING *
        `

    let values = [user.id, transaction_type, amount, source, transaction_date || null]

    try {
        const rowInserted = await con.query(q, values)
        res.status(201).send(rowInserted.rows)

    } catch (error) {
        console.log("Error frome the Database : ", error)
        res.status(500).send({ message: "Error frome the Database" })
    }

})

app.put("/edit-transaction", async (req, res) => {
    console.log(req.body)
    let user
    try {
        user = auth(req, res)
    } catch (error) {
        res.status(401).send({ message: error.message })
        return
    }

    let transaction_info = {}

    try {
        transaction_info = checkTransactionObject(req.body, ["transaction_id", "transaction_type", "amount", "source"])
    } catch (error) {
        res.status(400).send({ message: error.message })
        return
    }
    const { transaction_id, transaction_type, amount, source, transaction_date } = transaction_info

    let q = `UPDATE  transactions 
    SET transaction_type = $1,
    amount = $2,
    source = $3,
    transaction_date = $4
    WHERE user_id = $5 AND transaction_id = $6
    RETURNING *
    `

    let values = [transaction_type, amount, source, transaction_date || null, user.id, transaction_id]

    try {
        const rowEdited = await con.query(q, values)
        if (rowEdited.rowCount === 0) {
            res.status(404).send({ message: "No transaction found" })
            return
        }
        res.status(200).send(rowEdited.rows)
        return
    } catch (error) {
        console.log("Error from the Database trying to edit: ", error)
        res.status(500).send({ message: `Error from the Database trying to edit` })
        return
    }
})


app.delete("/delete-transaction", async (req, res) => {
    const transaction_id = req.query.id
    let user
    try {
        user = auth(req, res)
    } catch (error) {
        res.status(401).send({ message: error.message })
        return
    }

    console.log(transaction_id, "Will delete it")

    let selectq = `SELECT * FROM transactions 
    WHERE user_id = $1 AND transaction_id = $2`
    try {
        const selectResult = await con.query(selectq, [user.id, transaction_id])
        if (selectResult.rowCount <= 0) {
            res.status(404).send({ message: `The item does not exist` })
            return
        }
    } catch (error) {
        console.log("Error from the Database : ", error)
        res.status(500).send({ message: "Error from the Database : " })
        return
    }
    let deleteq = `DELETE FROM transactions 
    WHERE user_id = $1 AND transaction_id = $2
    RETURNING *
    `

    try {
        const deletResult = await con.query(deleteq, [user.id, transaction_id])
        res.status(200).send(deletResult.rows)
    } catch (error) {
        console.log("Error frome the Database : ", error)
        res.status(500).send({ message: "Error from the Database" })
    }
})




app.use((req, res, next) => {
    res.status(404).send({ message: "the endpoint doesn't exist" })
})

app.listen(3100, () => { console.log("Server is running") })

testDatabaseConection()

// app.get("/search", (req, res) => {

// })

