const jsonServer = require("json-server"); // importing json-server library
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const server = jsonServer.create();
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults();
const port = process.env.PORT || 8080; //  chose port from here like 8080, 3001

// Chave secreta para assinar os tokens JWT
const JWT_SECRET = "sua_chave_secreta_muito_segura";

// Configuração do CORS
server.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  
  // Responde imediatamente para requisições OPTIONS (preflight)
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  
  next();
});

// Middleware para processar JSON
server.use(jsonServer.bodyParser);
server.use(middlewares);

// Função para gerar hash da senha
async function hashPassword(password) {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
}

// Função para verificar senha
async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// Função para gerar token JWT
function generateToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
    },
    JWT_SECRET,
    { expiresIn: "24h" } // Token expira em 24 horas
  );
}

// Rota de registro de usuário
server.post("/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email e senha são obrigatórios" });
  }

  const db = router.db;
  const users = db.get("users").value();

  // Verifica se o email já está em uso
  if (users.some((user) => user.email === email)) {
    return res.status(400).json({ error: "Email já está em uso" });
  }

  try {
    const hashedPassword = await hashPassword(password);
    const newUser = {
      id: users.length + 1,
      email,
      password: hashedPassword,
      userData: {
        default_trainings: { ids: [] },
        edited_trainings: [],
        notifications: [],
        profile: {
          metadados: {
            termos: false,
            data_cadastro: new Date().toISOString(),
            xp: 0,
            conquistas: [],
          },
          objetivos: {},
          pessoal: {},
        },
        registered_trainings: [],
      },
    };

    db.get("users").push(newUser).write();

    // Gera o token JWT para o novo usuário
    const token = generateToken(newUser);

    res.status(201).json({
      message: "Usuário criado com sucesso",
      userId: newUser.id,
      token,
    });
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar usuário" });
  }
});

// Rota de login
server.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email e senha são obrigatórios" });
  }

  const db = router.db;
  const user = db.get("users").find({ email }).value();

  if (!user) {
    return res.status(401).json({ error: "Usuário não encontrado" });
  }

  try {
    const isValid = await verifyPassword(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: "Senha incorreta" });
    }

    // Gera o token JWT
    const token = generateToken(user);

    // Retorna os dados do usuário (exceto a senha) e o token
    const { password: _, ...userWithoutPassword } = user;
    res.json({
      user: userWithoutPassword,
      token,
    });
  } catch (error) {
    res.status(500).json({ error: "Erro ao fazer login" });
  }
});

// New endpoints to add to the webserver

// Get user data
server.get("/users/:id/data", async (req, res) => {
  const userId = parseInt(req.params.id);
  const db = router.db;
  const user = db.get("users").find({ id: userId }).value();

  if (!user) {
    return res.status(404).json({ error: "Usuário não encontrado" });
  }

  res.json(user.userData);
});

// Update user data
server.patch("/users/:id/data", async (req, res) => {
  const userId = parseInt(req.params.id);
  const db = router.db;
  const user = db.get("users").find({ id: userId }).value();

  if (!user) {
    return res.status(404).json({ error: "Usuário não encontrado" });
  }

  user.userData = { ...user.userData, ...req.body };
  db.get("users").find({ id: userId }).assign(user).write();

  res.json(user.userData);
});

// Add notification
server.post("/users/:id/notifications", async (req, res) => {
  const userId = parseInt(req.params.id);
  const db = router.db;
  const user = db.get("users").find({ id: userId }).value();

  if (!user) {
    return res.status(404).json({ error: "Usuário não encontrado" });
  }

  const notification = {
    ...req.body,
    dateTime: new Date().toISOString(),
  };

  user.userData.notifications.unshift(notification);
  db.get("users").find({ id: userId }).assign(user).write();

  res.json(notification);
});

// Delete notification
server.delete("/users/:id/notifications/:index", async (req, res) => {
  const userId = parseInt(req.params.id);
  const notificationIndex = parseInt(req.params.index);
  const db = router.db;
  const user = db.get("users").find({ id: userId }).value();

  if (!user) {
    return res.status(404).json({ error: "Usuário não encontrado" });
  }

  user.userData.notifications.splice(notificationIndex, 1);
  db.get("users").find({ id: userId }).assign(user).write();

  res.json({ message: "Notificação removida com sucesso" });
});

// Register training
server.post("/users/:id/trainings", async (req, res) => {
  const userId = parseInt(req.params.id);
  const db = router.db;
  const user = db.get("users").find({ id: userId }).value();

  if (!user) {
    return res.status(404).json({ error: "Usuário não encontrado" });
  }

  const training = {
    ...req.body,
    date: new Date().toISOString(),
  };

  user.userData.registered_trainings.push(training);
  db.get("users").find({ id: userId }).assign(user).write();

  res.json(training);
});

server.use(router);

server.listen(port, () => {
  console.log(`JSON Server está rodando na porta ${port}`);
});
