const express = require("express");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const session = require("express-session");
const multer = require("multer");
const fs = require("fs");

const app = express();
const PORT = 3000;

const db = new sqlite3.Database("./primora.db");

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            bio TEXT DEFAULT '',
            avatar TEXT DEFAULT '',
            tipo TEXT DEFAULT 'assinante',
            criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            descricao TEXT DEFAULT '',
            imagem TEXT DEFAULT '',
            exclusivo INTEGER DEFAULT 0,
            usuario_id INTEGER NOT NULL,
            criado_em DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
        )
    `);
});

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, "uploads"));
    },
    filename: function (req, file, cb) {
        const nome = Date.now() + "-" + Math.round(Math.random() * 1E9);
        const extensao = path.extname(file.originalname);
        cb(null, nome + extensao);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024
    },
    fileFilter: function (req, file, cb) {
        const permitidos = /jpeg|jpg|png|gif|webp/;
        const extensao = permitidos.test(path.extname(file.originalname).toLowerCase());
        const tipo = permitidos.test(file.mimetype);

        if (extensao && tipo) {
            cb(null, true);
        } else {
            cb(new Error("Apenas imagens são permitidas."));
        }
    }
});

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

app.use(session({
    secret: "primora-segredo-local",
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24
    }
}));

function usuarioLogado(req, res, next) {
    if (!req.session.usuario) {
        return res.redirect("/login");
    }
    next();
}

function carregarUsuario(req, callback) {
    if (!req.session.usuario) return callback(null, null);

    db.get(
        "SELECT id, nome, email, bio, avatar, tipo FROM usuarios WHERE id = ?",
        [req.session.usuario.id],
        callback
    );
}

app.get("/", (req, res) => {
    db.all(`
        SELECT posts.*, usuarios.nome, usuarios.avatar
        FROM posts
        JOIN usuarios ON usuarios.id = posts.usuario_id
        ORDER BY posts.id DESC
    `, (err, posts) => {
        carregarUsuario(req, (erroUsuario, usuario) => {
            res.render("index", {
                posts: posts || [],
                usuario: usuario || null
            });
        });
    });
});

app.get("/cadastro", (req, res) => {
    res.render("cadastro", { erro: null });
});

app.post("/cadastro", async (req, res) => {
    const { nome, email, senha, tipo } = req.body;

    if (!nome || !email || !senha) {
        return res.render("cadastro", {
            erro: "Preencha todos os campos."
        });
    }

    if (senha.length < 6) {
        return res.render("cadastro", {
            erro: "A senha precisa ter pelo menos 6 caracteres."
        });
    }

    const senhaCriptografada = await bcrypt.hash(senha, 10);

    db.run(
        `INSERT INTO usuarios (nome, email, senha, tipo)
         VALUES (?, ?, ?, ?)`,
        [nome, email, senhaCriptografada, tipo === "criador" ? "criador" : "assinante"],
        function (err) {
            if (err) {
                return res.render("cadastro", {
                    erro: "Este e-mail já está cadastrado."
                });
            }

            req.session.usuario = {
                id: this.lastID,
                nome,
                email
            };

            res.redirect("/painel");
        }
    );
});

app.get("/login", (req, res) => {
    res.render("login", { erro: null });
});

app.post("/login", (req, res) => {
    const { email, senha } = req.body;

    db.get(
        "SELECT * FROM usuarios WHERE email = ?",
        [email],
        async (err, usuario) => {
            if (err || !usuario) {
                return res.render("login", {
                    erro: "E-mail ou senha incorretos."
                });
            }

            const senhaValida = await bcrypt.compare(senha, usuario.senha);

            if (!senhaValida) {
                return res.render("login", {
                    erro: "E-mail ou senha incorretos."
                });
            }

            req.session.usuario = {
                id: usuario.id,
                nome: usuario.nome,
                email: usuario.email
            };

            res.redirect("/painel");
        }
    );
});

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/");
    });
});

app.get("/painel", usuarioLogado, (req, res) => {
    carregarUsuario(req, (err, usuario) => {
        db.all(
            "SELECT * FROM posts WHERE usuario_id = ? ORDER BY id DESC",
            [req.session.usuario.id],
            (erroPosts, posts) => {
                res.render("painel", {
                    usuario,
                    posts: posts || [],
                    erro: null,
                    sucesso: null
                });
            }
        );
    });
});

app.post("/perfil", usuarioLogado, upload.single("avatar"), (req, res) => {
    const { nome, bio, tipo } = req.body;
    const avatar = req.file ? "/uploads/" + req.file.filename : null;

    let sql;
    let parametros;

    if (avatar) {
        sql = `
            UPDATE usuarios
            SET nome = ?, bio = ?, tipo = ?, avatar = ?
            WHERE id = ?
        `;
        parametros = [nome, bio || "", tipo || "assinante", avatar, req.session.usuario.id];
    } else {
        sql = `
            UPDATE usuarios
            SET nome = ?, bio = ?, tipo = ?
            WHERE id = ?
        `;
        parametros = [nome, bio || "", tipo || "assinante", req.session.usuario.id];
    }

    db.run(sql, parametros, () => {
        req.session.usuario.nome = nome;
        res.redirect("/painel");
    });
});

app.post("/publicar", usuarioLogado, upload.single("imagem"), (req, res) => {
    const { titulo, descricao, exclusivo } = req.body;
    const imagem = req.file ? "/uploads/" + req.file.filename : "";

    if (!titulo) {
        return res.redirect("/painel");
    }

    db.run(
        `INSERT INTO posts
         (titulo, descricao, imagem, exclusivo, usuario_id)
         VALUES (?, ?, ?, ?, ?)`,
        [
            titulo,
            descricao || "",
            imagem,
            exclusivo === "on" ? 1 : 0,
            req.session.usuario.id
        ],
        () => {
            res.redirect("/painel");
        }
    );
});

app.post("/excluir-post/:id", usuarioLogado, (req, res) => {
    db.get(
        "SELECT * FROM posts WHERE id = ? AND usuario_id = ?",
        [req.params.id, req.session.usuario.id],
        (err, post) => {
            if (post && post.imagem) {
                const caminho = path.join(__dirname, post.imagem);

                if (fs.existsSync(caminho)) {
                    fs.unlinkSync(caminho);
                }
            }

            db.run(
                "DELETE FROM posts WHERE id = ? AND usuario_id = ?",
                [req.params.id, req.session.usuario.id],
                () => res.redirect("/painel")
            );
        }
    );
});

app.get("/criador/:id", (req, res) => {
    db.get(
        "SELECT id, nome, email, bio, avatar, tipo FROM usuarios WHERE id = ?",
        [req.params.id],
        (err, criador) => {
            if (!criador) {
                return res.status(404).send("Criador não encontrado.");
            }

            db.all(
                `SELECT posts.*, usuarios.nome
                 FROM posts
                 JOIN usuarios ON usuarios.id = posts.usuario_id
                 WHERE usuario_id = ?
                 ORDER BY posts.id DESC`,
                [req.params.id],
                (erro, posts) => {
                    res.render("criador", {
                        criador,
                        posts: posts || []
                    });
                }
            );
        }
    );
});


const servidor = app.listen(PORT, "0.0.0.0", () => {
    console.log("=================================");
    console.log("PRIMORA FUNCIONANDO!");
    console.log(`http://localhost:${PORT}`);
    console.log("=================================");
});

servidor.on("error", (erro) => {
    console.error("Erro no servidor:", erro);
});
