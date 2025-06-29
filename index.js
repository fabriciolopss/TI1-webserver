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
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Methods",
    "GET, POST, PATCH, PUT, DELETE, OPTIONS"
  );
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );

  // Responde imediatamente para requisições OPTIONS (preflight)
  if (req.method === "OPTIONS") {
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

// Função para verificar token JWT
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// Middleware para verificar autenticação
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: "Token de acesso necessário" });
  }

  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(403).json({ error: "Token inválido ou expirado" });
  }

  req.user = decoded;
  next();
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
        edited_trainings: [
          {
            id: 1,
            name: "Treino de inferiores",
            category: "Pernas",
            type: "Ficha iniciante",
            days: [
              {
                id: 1,
                xp: 100,
                name: "Dia 1 - Gluteos e Posterior de Coxa",
                day: [
                  { exercise: "Supino reto", series: 4, repetitions: "8-12" },
                  {
                    exercise: "Supino inclinado",
                    series: 4,
                    repetitions: "8-12",
                  },
                  {
                    exercise: "Supino transversal",
                    series: 4,
                    repetitions: "8-12",
                  },
                ],
              },
              {
                id: 2,
                xp: 150,
                name: "Dia 2 - Quadriceps e Panturrilha",
                day: [
                  { exercise: "Supino reto", series: 4, repetitions: "8-12" },
                  {
                    exercise: "Supino inclinado",
                    series: 4,
                    repetitions: "8-12",
                  },
                  {
                    exercise: "Supino transversal",
                    series: 4,
                    repetitions: "8-12",
                  },
                ],
              },
            ],
          },
          {
            id: 2,
            name: "Treino de superiores",
            category: "Superiores",
            type: "Ficha intermediária",
            days: [
              {
                id: 1,
                xp: 50,
                name: "Dia 1 - Costas",
                day: [
                  { exercise: "Supino reto", series: 4, repetitions: "8-12" },
                  {
                    exercise: "Supino inclinado",
                    series: 4,
                    repetitions: "8-12",
                  },
                  {
                    exercise: "Supino transversal",
                    series: 4,
                    repetitions: "8-12",
                  },
                ],
              },
              {
                id: 2,
                xp: 75,
                name: "Dia 2 - Ombro",
                day: [
                  { exercise: "Supino reto", series: 4, repetitions: "8-12" },
                  {
                    exercise: "Supino inclinado",
                    series: 4,
                    repetitions: "8-12",
                  },
                  {
                    exercise: "Supino transversal",
                    series: 4,
                    repetitions: "8-12",
                  },
                ],
              },
            ],
          },
        ],
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

// Get user data (protegida)
server.get("/users/:id/data", authenticateToken, async (req, res) => {
  const userId = parseInt(req.params.id);

  // Verifica se o usuário está tentando acessar seus próprios dados
  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Acesso negado" });
  }

  const db = router.db;
  const user = db.get("users").find({ id: userId }).value();

  if (!user) {
    return res.status(404).json({ error: "Usuário não encontrado" });
  }

  const allUsers = db.get("users").value();
  const totalTrainings = allUsers.reduce((sum, u) => {
    const trainings = u.userData?.registered_trainings || [];
    return sum + trainings.length;
  }, 0);
  const userCount = allUsers.length;

  const averageTrainingsPerUser =
    userCount > 0 ? parseFloat((totalTrainings / userCount).toFixed(2)) : 0;

  res.json({
    ...user.userData,
    media_treinos_por_usuario: averageTrainingsPerUser,
  });
});

// Update user data (protegida)
server.patch("/users/:id/data", authenticateToken, async (req, res) => {
  const userId = parseInt(req.params.id);

  // Verifica se o usuário está tentando acessar seus próprios dados
  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Acesso negado" });
  }

  const db = router.db;
  const user = db.get("users").find({ id: userId }).value();

  if (!user) {
    return res.status(404).json({ error: "Usuário não encontrado" });
  }

  user.userData = { ...user.userData, ...req.body };
  db.get("users").find({ id: userId }).assign(user).write();

  res.json(user.userData);
});

server.post("/test-auth", (req, res) => {
  // Rota para testar se o token é válido
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      valid: false,
      error: "Token de acesso necessário",
    });
  }

  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(403).json({
      valid: false,
      error: "Token inválido ou expirado",
    });
  }

  // Token é válido, retorna informações do usuário
  res.json({
    valid: true,
    user: {
      userId: decoded.userId,
      email: decoded.email,
    },
    message: "Token válido",
  });
});

// Add notification (protegida)
server.post("/users/:id/notifications", authenticateToken, async (req, res) => {
  const userId = parseInt(req.params.id);

  // Verifica se o usuário está tentando acessar seus próprios dados
  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Acesso negado" });
  }

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

// Delete notification (protegida)
server.delete(
  "/users/:id/notifications/:index",
  authenticateToken,
  async (req, res) => {
    const userId = parseInt(req.params.id);

    // Verifica se o usuário está tentando acessar seus próprios dados
    if (req.user.userId !== userId) {
      return res.status(403).json({ error: "Acesso negado" });
    }

    const notificationIndex = parseInt(req.params.index);
    const db = router.db;
    const user = db.get("users").find({ id: userId }).value();

    if (!user) {
      return res.status(404).json({ error: "Usuário não encontrado" });
    }

    user.userData.notifications.splice(notificationIndex, 1);
    db.get("users").find({ id: userId }).assign(user).write();

    res.json({ message: "Notificação removida com sucesso" });
  }
);

// Register training (protegida)
server.post("/users/:id/trainings", authenticateToken, async (req, res) => {
  const userId = parseInt(req.params.id);

  // Verifica se o usuário está tentando acessar seus próprios dados
  if (req.user.userId !== userId) {
    return res.status(403).json({ error: "Acesso negado" });
  }

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

server.get("/ranking", async (req, res) => {
  const db = router.db;
  const users = db.get("users").value();

  // Monta o ranking com nome/email e XP
  const ranking = users.map((user) => ({
    id: user.id,
    email: user.email,
    xp:
      user.userData?.profile?.xp || user.userData?.profile?.metadados?.xp || 0,
  }));

  // Ordena do maior para o menor XP
  ranking.sort((a, b) => b.xp - a.xp);

  res.json(ranking);
});

// Get all users (for social feed)
server.get("/users", async (req, res) => {
  const db = router.db;
  const users = db.get("users").value();

  // Retorna apenas dados necessários para o feed social
  const socialUsers = users.map((user) => ({
    id: user.id,
    email: user.email,
    userData: user.userData,
  }));

  res.json(socialUsers);
});

// Get social feed
server.get("/social-feed", async (req, res) => {
  const db = router.db;
  const users = db.get("users").value();
  const postInfos = [];

  const page = parseInt(req.query.page) + 1 || 1;
  const limit = parseInt(req.query.limit) || 10;
  const startIndex = (page - 1) * limit;
  const endIndex = page * limit;

  users.forEach((user) => {
    (user.userData?.registered_trainings || []).forEach((training) => {
      const dayName = new Date(training.date).toLocaleDateString("pt-BR", {
        weekday: "long",
      });

      const editedTraining =
        user.userData?.edited_trainings?.[training.training_id - 1];
      if (!editedTraining) return;

      const trainingDay = editedTraining.days?.[training.day_index];
      if (!trainingDay) return;

      postInfos.push({
        userId: user.id,
        name: user.userData.profile?.pessoal.nome || user.email,
        training: trainingDay,
        category: editedTraining.category || "Cardio",
        message: generateMessage(editedTraining.category || "Cardio", dayName),
        date: new Date(training.date).toISOString(),
        duration: formatDuration(
          training.duration || { hours: 0, minutes: 30 }
        ),
        timeAgo: getTimeAgo(new Date(training.date)),
        xpTotal: user.userData?.profile?.xp || 0,
        xpGained: training.xpGain || 0,
      });
    });
  });

  postInfos.sort((a, b) => new Date(b.date) - new Date(a.date));

  const paginatedPosts = postInfos.slice(startIndex, endIndex);

  res.json({
    feed: paginatedPosts,
    pagination: {
      totalItems: postInfos.length,
      totalPages: Math.ceil(postInfos.length / limit),
      currentPage: page,
      perPage: limit,
    },
  });
});

// Funções auxiliares para o feed social
function formatDuration(duration) {
  const hours = duration.hours || 0;
  const minutes = duration.minutes || 0;

  if (hours > 0) {
    return `${hours}h ${minutes}min`;
  }
  return `${minutes} minutos`;
}

function getTimeAgo(date) {
  const now = new Date();
  const diffMs = now - date;
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHours = Math.floor(diffMin / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffSec < 60) return `${diffSec} segundo${diffSec > 1 ? "s" : ""} atrás`;
  if (diffMin < 60) return `${diffMin} minuto${diffMin > 1 ? "s" : ""} atrás`;
  if (diffHours < 24)
    return `${diffHours} hora${diffHours > 1 ? "s" : ""} atrás`;
  if (diffDays < 7) return `${diffDays} dia${diffDays > 1 ? "s" : ""} atrás`;

  const diffWeeks = Math.floor(diffDays / 7);
  return `${diffWeeks} semana${diffWeeks > 1 ? "s" : ""} atrás`;
}

function calculateLevel(xp) {
  return Math.floor(xp / 100) + 1;
}

function generateMessage(category, dayName) {
  const messages = {
    Cardio: [
      `Treino de cardio incrível! 🔥 ${dayName} concluído com sucesso! #Cardio #Fitness`,
      `Mais um dia de cardio! 💪 ${dayName} - queimando calorias e construindo resistência! #Motivado`,
      `Cardio intenso hoje! 🏃‍♂️ ${dayName} - cada gota de suor vale a pena! #Resultados`,
    ],
    Pernas: [
      `Treino de pernas épico! 🦵 ${dayName} - sentindo cada músculo trabalhando! #Pernas #Força`,
      `Inferiores no foco! 💪 ${dayName} - construindo pernas de aço! #Treino #Evolução`,
      `Pernas de ferro! 🏋️‍♂️ ${dayName} - progresso constante é a chave! #Motivado`,
    ],
    Superiores: [
      `Superiores no ponto! 💪 ${dayName} - força e definição em construção! #Superiores #Fitness`,
      `Treino de superiores incrível! 🏋️‍♂️ ${dayName} - cada repetição conta! #Força #Progresso`,
      `Superiores concluídos! 🔥 ${dayName} - evolução constante! #Treino #Resultados`,
    ],
    Funcional: [
      `Funcional intenso! 🎯 ${dayName} - trabalhando todo o corpo de forma integrada! #Funcional #Saúde`,
      `Circuito funcional incrível! 💪 ${dayName} - equilíbrio, força e resistência! #Funcional #Completo`,
      `Funcional no foco! 🔥 ${dayName} - movimento funcional é vida! #Funcional #Fitness`,
    ],
  };

  const categoryMessages = messages[category] || messages["Cardio"];
  return categoryMessages[Math.floor(Math.random() * categoryMessages.length)];
}

server.use(router);

server.listen(port, () => {
  console.log(`JSON Server está rodando na porta ${port}`);
});
