import express, { Request, Response } from "express";
import cors from "cors";
import axios from "axios";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import path from "path";
import * as fs from "fs";
import * as crypto from "crypto";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Servir a interface gráfica (login do integrador)
app.use(express.static(path.join(__dirname, "..", "public")));

const SECRET = process.env.JWT_SECRET || "integrador_secret_123";
const PORT = process.env.PORT || 8080;

// --- GERAÇÃO E CARREGAMENTO DE CHAVES RSA M2M ---
const privateKeyPath = path.join(__dirname, "..", "private_key.pem");
const publicKeyPath = path.join(__dirname, "..", "public_key.pem");
let privateKey = "";

if (fs.existsSync(privateKeyPath)) {
  privateKey = fs.readFileSync(privateKeyPath, "utf8");
} else {
  console.log("Gerando novas chaves RSA para M2M...");
  const { privateKey: pKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  privateKey = pKey;
  fs.writeFileSync(privateKeyPath, privateKey);
  fs.writeFileSync(publicKeyPath, publicKey);
  console.log("⚠️ AVISO: Chaves RSA geradas! Envie o arquivo public_key.pem para a API de Lutas!");
}

function generateRSASignature(rota: string) {
  const mensagem = `api_integrador:${rota}`;
  const assinatura = crypto.sign("sha256", Buffer.from(mensagem), {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING
  });
  return assinatura.toString("base64");
}

type InstanceConfig = { url: string; user: string; pass: string };

// Lista de instâncias (Microserviços) com suas credenciais de acesso individuais
const INSTANCES: Record<string, InstanceConfig[]> = {
  apostadores: [
    { url: "https://api-apostadores-fight-azure.vercel.app", user: "admin", pass: "123" }
  ],
  lutadores: [
    { url: "https://api-lutadoressd.onrender.com/api", user: "", pass: "" } // API Externa de Lutadores (Pública)
  ],
  lutas: [
    { url: "https://betting-api-hmup.onrender.com", user: "", pass: "" } // API Restrita (RSA)
  ],
  apostas: []
};

/*
  ROTA DE LOGIN DO INTEGRADOR
*/
app.post("/login", (req: Request, res: Response): any => {
  const { username, password } = req.body;
  if (username === "admin" && password === "admin") {
    const token = jwt.sign({ id: 1, role: "integrador" }, SECRET, { expiresIn: "2h" });
    return res.json({ token });
  }
  return res.status(401).json({ erro: "Credenciais inválidas" });
});

/*
  MIDDLEWARE INTERNO
*/
const requireAuth = (req: Request, res: Response, next: express.NextFunction) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ erro: "Acesso negado no Gateway" });
  
  try {
    jwt.verify(token, SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ erro: "Token inválido no Gateway" });
  }
};

/*
  FUNÇÃO AUXILIAR: Autenticar o Gateway nas Instâncias das APIs filhas
*/
async function authenticateWithInstance(instance: InstanceConfig): Promise<string | null> {
  if (!instance.user || !instance.pass) return "NO_AUTH"; // Não requer autenticação
  
  try {
    const res = await axios.post(`${instance.url}/login`, {
      usuario: instance.user,
      senha: instance.pass
    }, { timeout: 3000 });
    
    // Suporta tanto o formato do Node (token) quanto possível padrão do FastAPI (access_token)
    return res.data.token || res.data.access_token;
  } catch (err) {
    console.log(`[Integrador] Falha ao autenticar na instância: ${instance.url}`);
    return null;
  }
}

/*
  FUNÇÃO AUXILIAR: Buscar em TODAS as instâncias e Unificar os Dados (Merge)
*/
async function forwardGetRequest(category: string, urlPath: string) {
  const targetInstances = INSTANCES[category];
  if (!targetInstances || targetInstances.length === 0) return [];
  
  const promises = targetInstances.map(async (instance) => {
    try {
      const instanceToken = await authenticateWithInstance(instance);
      if (!instanceToken) return { success: false, data: null };

      const headers: any = {};
      if (instanceToken !== "NO_AUTH") {
        headers.Authorization = `Bearer ${instanceToken}`;
      }
      
      // Autenticação RSA para a API de Lutas
      if (category === "lutas") {
        headers["x-api-nome"] = "api_integrador";
        headers["x-assinatura"] = generateRSASignature(urlPath);
      }

      const res = await axios.get(`${instance.url}${urlPath}`, {
        headers,
        timeout: 60000
      });
      return { success: true, data: res.data };
    } catch (err) {
      console.log(`[Integrador] Falha ao ler da instância: ${instance.url}${urlPath}`);
      return { success: false, data: null };
    }
  });

  const results = await Promise.all(promises);
  
  // Extrai as respostas bem sucedidas
  const successfulData = results.filter(r => r.success).map(r => r.data);

  if (successfulData.length === 0) {
    throw new Error(`Nenhuma instância de ${category} conseguiu retornar os dados.`);
  }

  // Se o endpoint retornar uma ARRAY (Listar Todos)
  if (Array.isArray(successfulData[0])) {
    let mergedArray: any[] = [];
    successfulData.forEach(array => {
      if (Array.isArray(array)) {
        mergedArray = mergedArray.concat(array);
      }
    });

    // Filtra IDs duplicados (já que os dados devem estar em ambas as APIs)
    const uniqueItemsMap = new Map();
    mergedArray.forEach(item => {
      if (item && item.id) {
        uniqueItemsMap.set(item.id, item);
      }
    });
    return Array.from(uniqueItemsMap.values());
  }

  // Se for um Objeto (Busca por ID), retorna o primeiro válido encontrado
  return successfulData[0];
}

/*
  FUNÇÃO AUXILIAR: Replicar comando de ESCRITA para TODAS as instâncias
*/
async function replicateWriteRequest(category: string, method: string, urlPath: string, data: any) {
  const targetInstances = INSTANCES[category];
  if (!targetInstances || targetInstances.length === 0) throw new Error(`Nenhuma instância configurada para ${category}.`);
  
  const promises = targetInstances.map(async (instance) => {
    try {
      const instanceToken = await authenticateWithInstance(instance);
      if (!instanceToken) throw new Error("Não foi possível autenticar na instância.");

      const headers: any = {};
      if (instanceToken !== "NO_AUTH") {
        headers.Authorization = `Bearer ${instanceToken}`;
      }
      
      if (category === "lutas") {
        headers["x-api-nome"] = "api_integrador";
        headers["x-assinatura"] = generateRSASignature(urlPath);
      }

      const res = await axios({
        method,
        url: `${instance.url}${urlPath}`,
        data,
        headers,
        timeout: 60000
      });
      return { status: "sucesso", instance: instance.url, data: res.data };
    } catch (err: any) {
      console.log(`[Integrador] Falha ao replicar para a instância de ${category}: ${instance.url}${urlPath}`);
      return { status: "erro", instance: instance.url, error: err.message };
    }
  });

  const results = await Promise.all(promises);
  const successCount = results.filter(r => r.status === "sucesso").length;

  if (successCount === 0) {
    throw new Error(`Nenhuma instância de ${category} conseguiu processar os dados.`);
  }

  return results;
}

/*
  =========================================
  ROTAS DE PROXY PARA AS CATEGORIAS
  =========================================
*/

function setupCategoryRoutes(categoryName: string, endpoint: string) {
  
  app.get(`/api/${endpoint}`, requireAuth, async (req: Request, res: Response): Promise<any> => {
    try {
      const data = await forwardGetRequest(categoryName, `/${endpoint}`);
      return res.json(data);
    } catch (err: any) {
      return res.status(503).json({ erro: err.message });
    }
  });

  app.get(`/api/${endpoint}/:id`, requireAuth, async (req: Request, res: Response): Promise<any> => {
    try {
      const data = await forwardGetRequest(categoryName, `/${endpoint}/${req.params.id}`);
      return res.json(data);
    } catch (err: any) {
      return res.status(503).json({ erro: err.message });
    }
  });

  app.post(`/api/${endpoint}`, requireAuth, async (req: Request, res: Response): Promise<any> => {
    try {
      const results = await replicateWriteRequest(categoryName, "POST", `/${endpoint}`, req.body);
      return res.status(201).json({ mensagem: "Sucesso na replicação", relatorio: results });
    } catch (err: any) {
      return res.status(503).json({ erro: err.message });
    }
  });
  
  app.put(`/api/${endpoint}/:id`, requireAuth, async (req: Request, res: Response): Promise<any> => {
    try {
      const results = await replicateWriteRequest(categoryName, "PUT", `/${endpoint}/${req.params.id}`, req.body);
      return res.json({ mensagem: "Sucesso na replicação", relatorio: results });
    } catch (err: any) {
      return res.status(503).json({ erro: err.message });
    }
  });

  app.delete(`/api/${endpoint}/:id`, requireAuth, async (req: Request, res: Response): Promise<any> => {
    try {
      const results = await replicateWriteRequest(categoryName, "DELETE", `/${endpoint}/${req.params.id}`, null);
      return res.json({ mensagem: "Deleção replicada", relatorio: results });
    } catch (err: any) {
      return res.status(503).json({ erro: err.message });
    }
  });
}

// Inicializando as rotas das 4 categorias exigidas no contrato
setupCategoryRoutes("apostadores", "apostadores");
setupCategoryRoutes("lutadores", "lutadores");
setupCategoryRoutes("lutas", "lutas");
setupCategoryRoutes("apostas", "apostas");


// Inicia o Integrador
app.listen(PORT, () => {
  console.log(`🚀 Gateway Integrador rodando na porta ${PORT}`);
  console.log(`🔗 Interface de Login disponível em http://localhost:${PORT}`);
});
