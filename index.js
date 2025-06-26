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
                  { exercise: "Supino inclinado", series: 4, repetitions: "8-12" },
                  { exercise: "Supino transversal", series: 4, repetitions: "8-12" }
                ]
              },
              {
                id: 2,
                xp: 150,
                name: "Dia 2 - Quadriceps e Panturrilha",
                day: [
                  { exercise: "Supino reto", series: 4, repetitions: "8-12" },
                  { exercise: "Supino inclinado", series: 4, repetitions: "8-12" },
                  { exercise: "Supino transversal", series: 4, repetitions: "8-12" }
                ]
              }
            ]
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
                  { exercise: "Supino inclinado", series: 4, repetitions: "8-12" },
                  { exercise: "Supino transversal", series: 4, repetitions: "8-12" }
                ]
              },
              {
                id: 2,
                xp: 75,
                name: "Dia 2 - Ombro",
                day: [
                  { exercise: "Supino reto", series: 4, repetitions: "8-12" },
                  { exercise: "Supino inclinado", series: 4, repetitions: "8-12" },
                  { exercise: "Supino transversal", series: 4, repetitions: "8-12" }
                ]
              }
            ]
          }
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

server.get("/ranking", async (req, res) => {
  const db = router.db;
  const users = db.get("users").value();

  // Monta o ranking com nome/email e XP
  const ranking = users.map(user => ({
    id: user.id,
    email: user.email,
    xp: user.userData?.profile?.xp || user.userData?.profile?.metadados?.xp || 0
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
  const socialUsers = users.map(user => ({
    id: user.id,
    email: user.email,
    userData: user.userData
  }));

  res.json(socialUsers);
});

// Get social feed
server.get("/social-feed", async (req, res) => {
  const db = router.db;
  const users = db.get("users").value();
  
  const page = parseInt(req.query.page) || 0;
  const limit = parseInt(req.query.limit) || 10;
  const sortBy = req.query.sortBy || 'recent';
  const category = req.query.category || 'all';

  // Coleta todos os treinos registrados de todos os usuários
  let allTrainings = [];
  
  users.forEach(user => {
    if (user.userData?.registered_trainings) {
      user.userData.registered_trainings.forEach(training => {
        // Encontrar o treino correspondente
        const trainingData = user.userData.edited_trainings?.find(t => t.id == training.training_id);
        if (trainingData) {
          const day = trainingData.days?.find(d => d.id == training.day_index);
          if (day) {
            allTrainings.push({
              id: `${user.id}_${training.date}_${training.training_id}_${training.day_index}`,
              userId: user.id,
              userData: user.userData,
              training: trainingData,
              day: day,
              registeredTraining: training,
              trainingDate: new Date(training.date)
            });
          }
        }
      });
    }
  });

  // Aplicar filtros
  if (category !== 'all') {
    allTrainings = allTrainings.filter(item => 
      item.training.category === category
    );
  }

  // Aplicar ordenação
  switch (sortBy) {
    case 'recent':
      allTrainings.sort((a, b) => b.trainingDate - a.trainingDate);
      break;
    case 'xp':
      allTrainings.sort((a, b) => b.registeredTraining.xpGain - a.registeredTraining.xpGain);
      break;
    case 'popular':
      // Ordenar por XP do usuário (usuários com mais XP aparecem primeiro)
      allTrainings.sort((a, b) => {
        const aXp = a.userData?.profile?.xp || a.userData?.profile?.metadados?.xp || 0;
        const bXp = b.userData?.profile?.xp || b.userData?.profile?.metadados?.xp || 0;
        return bXp - aXp;
      });
      break;
  }

  // Aplicar paginação
  const startIndex = page * limit;
  const endIndex = startIndex + limit;
  const paginatedTrainings = allTrainings.slice(startIndex, endIndex);

  // Processar dados para o formato do feed
  const posts = paginatedTrainings.map(item => {
    const duration = item.registeredTraining.duration;
    const durationText = formatDuration(duration);
    const timeAgo = getTimeAgo(item.trainingDate);
    const message = generateMessage(item.training.category, item.day.name);
    
    // Verificar conquistas recentes
    const recentAchievements = item.userData.profile?.metadados?.conquistas?.filter(c => 
      c.conquistada && !c.resgatada
    ) || [];

    return {
      id: item.id,
      user: {
        id: item.userId,
        name: item.userData.profile?.pessoal?.nome || 'Usuário',
        level: calculateLevel(item.userData.profile?.xp || item.userData.profile?.metadados?.xp || 0),
        avatar: (item.userData.profile?.pessoal?.nome || 'U').charAt(0).toUpperCase()
      },
      workout: {
        title: item.training.name,
        category: item.training.category,
        day: item.day.name,
        duration: durationText,
        xp: item.registeredTraining.xpGain,
        exercises: item.day.day || []
      },
      timeAgo,
      message,
      achievement: recentAchievements.length > 0 ? {
        name: recentAchievements[0].nome,
        icon: 'trophy',
        new: true
      } : null,
      trainingDate: item.registeredTraining.date
    };
  });

  res.json({
    posts,
    total: allTrainings.length,
    page,
    limit,
    hasMore: endIndex < allTrainings.length
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

  if (diffSec < 60) return `${diffSec} segundo${diffSec > 1 ? 's' : ''} atrás`;
  if (diffMin < 60) return `${diffMin} minuto${diffMin > 1 ? 's' : ''} atrás`;
  if (diffHours < 24) return `${diffHours} hora${diffHours > 1 ? 's' : ''} atrás`;
  if (diffDays < 7) return `${diffDays} dia${diffDays > 1 ? 's' : ''} atrás`;
  
  const diffWeeks = Math.floor(diffDays / 7);
  return `${diffWeeks} semana${diffWeeks > 1 ? 's' : ''} atrás`;
}

function calculateLevel(xp) {
  return Math.floor(xp / 100) + 1;
}

function generateMessage(category, dayName) {
  const messages = {
    'Cardio': [
      `Treino de cardio incrível! 🔥 ${dayName} concluído com sucesso! #Cardio #Fitness`,
      `Mais um dia de cardio! 💪 ${dayName} - queimando calorias e construindo resistência! #Motivado`,
      `Cardio intenso hoje! 🏃‍♂️ ${dayName} - cada gota de suor vale a pena! #Resultados`
    ],
    'Pernas': [
      `Treino de pernas épico! 🦵 ${dayName} - sentindo cada músculo trabalhando! #Pernas #Força`,
      `Inferiores no foco! 💪 ${dayName} - construindo pernas de aço! #Treino #Evolução`,
      `Pernas de ferro! 🏋️‍♂️ ${dayName} - progresso constante é a chave! #Motivado`
    ],
    'Superiores': [
      `Superiores no ponto! 💪 ${dayName} - força e definição em construção! #Superiores #Fitness`,
      `Treino de superiores incrível! 🏋️‍♂️ ${dayName} - cada repetição conta! #Força #Progresso`,
      `Superiores concluídos! 🔥 ${dayName} - evolução constante! #Treino #Resultados`
    ],
    'Funcional': [
      `Funcional intenso! 🎯 ${dayName} - trabalhando todo o corpo de forma integrada! #Funcional #Saúde`,
      `Circuito funcional incrível! 💪 ${dayName} - equilíbrio, força e resistência! #Funcional #Completo`,
      `Funcional no foco! 🔥 ${dayName} - movimento funcional é vida! #Funcional #Fitness`
    ]
  };

  const categoryMessages = messages[category] || messages['Cardio'];
  return categoryMessages[Math.floor(Math.random() * categoryMessages.length)];
}

server.use(router);

server.listen(port, () => {
  console.log(`JSON Server está rodando na porta ${port}`);
});
