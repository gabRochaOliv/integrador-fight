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
const NOME_INTEGRADOR = process.env.NOME_INTEGRADOR || "api_integrador_node";

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

function generateRSASignature(rota: string, nome: string = NOME_INTEGRADOR) {
  const mensagem = `${nome}:${rota}`;
  const assinatura = crypto.sign("sha256", Buffer.from(mensagem), {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
  });
  return assinatura.toString("base64");
}

type InstanceConfig = {
  url: string; user: string; pass: string;
  loginPath?: string;        // caminho do endpoint de login (padrão: /login)
  trailingSlash?: boolean;
  nomeIntegrador?: string;
  useEncryption?: boolean;
  apiKey?: string;
  useRsaChunkResponse?: boolean; // respostas vêm como chunks RSA cifrados
  useQueryParams?: boolean;      // cria/atualiza via query string, sem body JSON
  handshakeEndpoint?: string;    // ex: "/handshake" — registra nossa chave pública antes de usar
  snakeCasePayload?: boolean;    // converte payload camelCase → snake_case antes de enviar
  shortLutadorFields?: boolean;  // usa lutador1/lutador2 em vez de id_lutador1/id_lutador2
  singleLutadorField?: boolean;  // usa id_lutador (singular) em vez de id_lutador1/id_lutador2
};

// Lista de instâncias (Microserviços) com suas credenciais de acesso individuais
const INSTANCES: Record<string, InstanceConfig[]> = {
  apostadores: [
    { url: "https://api-apostadores-fight-azure.vercel.app", user: "admin", pass: "123" },
    { url: "https://api-sd-df8o.onrender.com", user: "", pass: "", trailingSlash: true }
  ],
  lutadores: [
    { url: "https://api-lutadoressd.onrender.com/api", user: "", pass: "" },
    {
      url: "https://lutadores-api-22f61a69f511.herokuapp.com",
      user: "", pass: "",
      useRsaChunkResponse: true,
      useQueryParams: true,
      handshakeEndpoint: "/handshake"
    }
  ],
  lutas: [
    { url: "https://betting-api-beta.vercel.app", user: "", pass: "", trailingSlash: true },
    { url: "https://bet3m-production.up.railway.app", user: "", pass: "", apiKey: "bet3M-UENP", shortLutadorFields: true }
  ],
  apostas: [
    { url: "http://187.77.235.119:5555", user: "", pass: "", useEncryption: true },
    {
      url: "https://api-aposta-lutas.vercel.app",
      user: process.env.APOSTAS_USER || "",
      pass: process.env.APOSTAS_PASS || "",
      loginPath: "/auth/login",
      snakeCasePayload: true,
      singleLutadorField: true
    }
  ]
};

// --- HANDSHAKE + DECIFRAÇÃO RSA BIDIRECIONAL (NanadeFight) ---
const handshakeCache = new Set<string>();

// Par de chaves efêmero por instância — gerado em DER (sem headers PEM) para compatibilidade com Web Crypto
const rsaSessionKeys = new Map<string, { priv: crypto.KeyObject; pubB64: string }>();

function getOrCreateSessionKey(instanceUrl: string) {
  if (rsaSessionKeys.has(instanceUrl)) return rsaSessionKeys.get(instanceUrl)!;
  const { privateKey: priv, publicKey: pub } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "der" } as any,
    privateKeyEncoding: { type: "pkcs8", format: "der" } as any
  });
  const session = {
    priv: crypto.createPrivateKey({ key: priv as any, format: "der", type: "pkcs8" }),
    pubB64: (pub as any as Buffer).toString("base64")
  };
  rsaSessionKeys.set(instanceUrl, session);
  return session;
}

async function ensureHandshake(instance: InstanceConfig): Promise<void> {
  if (!instance.handshakeEndpoint || handshakeCache.has(instance.url)) return;
  const session = getOrCreateSessionKey(instance.url);
  await axios.post(
    `${instance.url}${instance.handshakeEndpoint}`,
    { publicKey: session.pubB64 },
    { headers: { "Content-Type": "application/json" }, timeout: 15000 }
  );
  handshakeCache.add(instance.url);
  console.log(`[Integrador] Handshake RSA concluído: ${instance.url}`);
}

function decryptRsaChunks(chunks: string[], privKey: crypto.KeyObject): any {
  const parts: Buffer[] = [];
  for (const chunk of chunks) {
    const decrypted = crypto.privateDecrypt(
      { key: privKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
      Buffer.from(chunk, "base64")
    );
    parts.push(decrypted);
  }
  const text = Buffer.concat(parts).toString("utf8");
  // Sanitiza valores corrompidos do tipo ""undefined"" → null (bug de dados da API)
  const sanitized = text.replace(/""([^"]*)""/g, (_, inner) => inner === "" ? '""' : `"${inner}"`);
  return JSON.parse(sanitized);
}

// --- CRIPTOGRAFIA HÍBRIDA RSA+AES (para APIs com X-Encrypted) ---
const publicKeyCache = new Map<string, string>();

async function fetchPublicKey(instanceUrl: string): Promise<string> {
  if (publicKeyCache.has(instanceUrl)) return publicKeyCache.get(instanceUrl)!;
  const res = await axios.get(`${instanceUrl}/crypto/public-key`, { timeout: 10000 });
  const pem = typeof res.data === "string" ? res.data : (res.data.publicKey || res.data.key || "");
  if (!pem) throw new Error(`Chave pública não encontrada em ${instanceUrl}/crypto/public-key`);
  publicKeyCache.set(instanceUrl, pem);
  return pem;
}

function encryptPayload(publicKeyPem: string, data: any): object {
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
  const encryptedData = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(data))), cipher.final()]);
  const encryptedKey = crypto.publicEncrypt(
    { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    aesKey
  );
  return {
    encryptedKey: encryptedKey.toString("base64"),
    iv: iv.toString("base64"),
    encryptedData: encryptedData.toString("base64")
  };
}

/*
  ROTA DE LOGIN DO INTEGRADOR
*/
app.post("/login", (req: Request, res: Response): any => {
  const { username, password } = req.body;
  if (username === "admin" && password === "admin") {
    const token = jwt.sign({ id: 1, role: "admin" }, SECRET, { expiresIn: "2h" });
    return res.json({ token, role: "admin" });
  }
  if (username === "user" && password === "user") {
    const token = jwt.sign({ id: 2, role: "user" }, SECRET, { expiresIn: "2h" });
    return res.json({ token, role: "user" });
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
    const loginPath = instance.loginPath || "/login";
    const res = await axios.post(`${instance.url}${loginPath}`, {
      usuario: instance.user,
      senha: instance.pass
    }, { timeout: 5000 });

    // Suporta tanto o formato do Node (token) quanto possível padrão do FastAPI (access_token)
    return res.data.token || res.data.access_token;
  } catch (err) {
    console.log(`[Integrador] Falha ao autenticar na instância: ${instance.url}`);
    return null;
  }
}

function toSnakeCase(obj: any): any {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return obj;
  return Object.fromEntries(
    Object.entries(obj).map(([k, v]) => [k.replace(/[A-Z]/g, c => '_' + c.toLowerCase()), v])
  );
}

function getShortName(url: string): string {
  try {
    const { hostname } = new URL(url);
    if (hostname === "187.77.235.119") return "NanaDeBets";
    if (hostname.includes("api-aposta-lutas")) return "ApostaLutas";
    if (hostname.includes("bet3m")) return "Bet3m";
    if (hostname.includes("betting-api-beta")) return "BettingBeta";
    if (hostname.includes("betting-api-lutas")) return "BettingLutas";
    if (hostname.includes("apostadores")) return "FightAzure";
    if (hostname.includes("api-sd")) return "ApiSD";
    if (hostname.includes("lutadores-api")) return "NanadeFight";
    if (hostname.includes("lutadores")) return "LutadoresSD";
    const first = hostname.split(".")[0].replace(/-/g, " ");
    return first.charAt(0).toUpperCase() + first.slice(1);
  } catch {
    return url;
  }
}

// --- LOGS DE REQUISIÇÕES ---
type LogEntry = {
  id: number; ts: string; method: string; path: string;
  instance: string; instanceName: string;
  status: 'ok' | 'erro'; ms: number; error?: string;
};
const logBuffer: LogEntry[] = [];
let logSeq = 0;
function addLog(e: Omit<LogEntry, 'id' | 'ts'>) {
  logBuffer.unshift({ id: ++logSeq, ts: new Date().toISOString(), ...e });
  if (logBuffer.length > 500) logBuffer.pop();
}

/*
  FUNÇÃO AUXILIAR: Buscar em TODAS as instâncias e Unificar os Dados (Merge)
*/
async function forwardGetRequest(category: string, urlPath: string) {
  const targetInstances = INSTANCES[category];
  if (!targetInstances || targetInstances.length === 0) return { data: [], instances: [] };

  const promises = targetInstances.map(async (instance) => {
    const name = getShortName(instance.url);
    const _t0 = Date.now();
    try {
      if (instance.handshakeEndpoint) await ensureHandshake(instance);

      const instanceToken = await authenticateWithInstance(instance);
      if (!instanceToken) return { success: false, data: null, name, url: instance.url };

      const headers: any = {};
      if (instanceToken !== "NO_AUTH") {
        headers.Authorization = `Bearer ${instanceToken}`;
      }

      const normalizedPath = instance.trailingSlash && !urlPath.endsWith('/') && !/\/\d+$/.test(urlPath)
        ? urlPath + '/'
        : urlPath;

      if (category === "lutas") {
        const nome = instance.nomeIntegrador || NOME_INTEGRADOR;
        headers["x-api-nome"] = nome;
        headers["x-assinatura"] = generateRSASignature(normalizedPath, nome);
      }

      if (instance.apiKey) headers["X-API-KEY"] = instance.apiKey;
      if (instance.useEncryption) headers["X-Encrypted"] = "true";

      const res = await axios.get(`${instance.url}${normalizedPath}`, { headers, timeout: 60000 });

      let responseData = res.data;
      if (instance.useRsaChunkResponse && Array.isArray(responseData) && responseData.every((c: any) => typeof c === "string")) {
        try {
          const session = getOrCreateSessionKey(instance.url);
          responseData = decryptRsaChunks(responseData, session.priv);
        } catch (decErr: any) {
          console.log(`[Integrador] Erro RSA decrypt: ${decErr.message}`);
          handshakeCache.delete(instance.url);
          rsaSessionKeys.delete(instance.url); // força novo par de chaves + handshake
          throw new Error("Falha ao decifrar resposta RSA");
        }
      }

      addLog({ method: 'GET', path: urlPath, instance: instance.url, instanceName: name, status: 'ok', ms: Date.now() - _t0 });
      return { success: true, data: responseData, name, url: instance.url };
    } catch (err: any) {
      const detail = err.response
        ? `HTTP ${err.response.status}: ${JSON.stringify(err.response.data)}`
        : err.message;
      console.log(`[Integrador] Falha ao ler da instância: ${instance.url}${urlPath} — ${detail}`);
      addLog({ method: 'GET', path: urlPath, instance: instance.url, instanceName: name, status: 'erro', ms: Date.now() - _t0, error: detail });
      return { success: false, data: null, name, url: instance.url };
    }
  });

  const results = await Promise.all(promises);
  const successful = results.filter(r => r.success);

  const instancesMeta = results.map(r => ({
    name: r.name,
    url: r.url,
    status: r.success ? "online" : "offline",
    count: r.success && Array.isArray(r.data) ? r.data.length : undefined
  }));

  if (successful.length === 0) {
    throw new Error(`Nenhuma instância de ${category} conseguiu retornar os dados.`);
  }

  // Se o endpoint retornar uma ARRAY (Listar Todos)
  if (Array.isArray(successful[0].data)) {
    let mergedArray: any[] = [];
    successful.forEach(r => {
      if (Array.isArray(r.data)) {
        mergedArray = mergedArray.concat(r.data.map((item: any) => ({ ...item, _source: r.name })));
      }
    });

    // Itens com mesmo ID vindos de múltiplas APIs: fundir campos e acumular fontes
    const uniqueItemsMap = new Map<any, any>();
    mergedArray.forEach(item => {
      const { _source, ...rest } = item;
      if (!item.id) return;
      if (!uniqueItemsMap.has(item.id)) {
        uniqueItemsMap.set(item.id, { ...rest, _sources: [_source] });
      } else {
        const existing = uniqueItemsMap.get(item.id);
        // campos existentes têm prioridade; novos campos preenchem lacunas
        uniqueItemsMap.set(item.id, {
          ...rest,
          ...existing,
          _sources: [...existing._sources, _source]
        });
      }
    });
    return { data: Array.from(uniqueItemsMap.values()), instances: instancesMeta };
  }

  // Se for um Objeto (Busca por ID), retorna o primeiro válido encontrado
  return { data: successful[0].data, instances: instancesMeta };
}

/*
  FUNÇÃO AUXILIAR: Replicar comando de ESCRITA para TODAS as instâncias
*/
async function replicateWriteRequest(category: string, method: string, urlPath: string, data: any) {
  const targetInstances = INSTANCES[category];
  if (!targetInstances || targetInstances.length === 0) throw new Error(`Nenhuma instância configurada para ${category}.`);

  const promises = targetInstances.map(async (instance) => {
    const _t0 = Date.now();
    try {
      if (instance.handshakeEndpoint) await ensureHandshake(instance);

      const instanceToken = await authenticateWithInstance(instance);
      if (!instanceToken) throw new Error("Não foi possível autenticar na instância.");

      const headers: any = {};
      if (instanceToken !== "NO_AUTH") {
        headers.Authorization = `Bearer ${instanceToken}`;
      }

      const normalizedPath = instance.trailingSlash && !urlPath.endsWith('/') && !/\/\d+$/.test(urlPath)
        ? urlPath + '/'
        : urlPath;

      if (category === "lutas") {
        const nome = instance.nomeIntegrador || NOME_INTEGRADOR;
        headers["x-api-nome"] = nome;
        headers["x-assinatura"] = generateRSASignature(normalizedPath, nome);
      }

      if (instance.apiKey) headers["X-API-KEY"] = instance.apiKey;

      let requestData = instance.snakeCasePayload ? toSnakeCase(data) : data;
      if (instance.shortLutadorFields && requestData) {
        const { id_lutador1, id_lutador2, ...rest } = requestData;
        requestData = { ...rest, ...(id_lutador1 !== undefined && { lutador1: id_lutador1 }), ...(id_lutador2 !== undefined && { lutador2: id_lutador2 }) };
      }
      if (instance.singleLutadorField && requestData) {
        const { id_lutador1, id_lutador2, ...rest } = requestData;
        requestData = { ...rest, ...(id_lutador1 !== undefined && { id_lutador: id_lutador1 }) };
      }
      let finalUrl = `${instance.url}${normalizedPath}`;

      if (instance.useQueryParams && requestData) {
        const params = new URLSearchParams(
          Object.entries(requestData)
            .filter(([_, v]) => v !== undefined && v !== null)
            .map(([k, v]) => [k, String(v)])
        );
        finalUrl = `${finalUrl}?${params.toString()}`;
        requestData = null;
      }

      if (instance.useEncryption) {
        headers["X-Encrypted"] = "true";
        if (requestData && (method === "POST" || method === "PUT")) {
          const pem = await fetchPublicKey(instance.url);
          requestData = encryptPayload(pem, requestData);
        }
      }

      const res = await axios({
        method,
        url: finalUrl,
        data: requestData,
        headers,
        timeout: 60000
      });

      let responseData = res.data;
      if (instance.useRsaChunkResponse && Array.isArray(responseData) && responseData.every((c: any) => typeof c === "string")) {
        try {
          responseData = decryptRsaChunks(responseData, getOrCreateSessionKey(instance.url).priv);
        } catch { handshakeCache.delete(instance.url); rsaSessionKeys.delete(instance.url); }
      }
      addLog({ method, path: urlPath, instance: instance.url, instanceName: getShortName(instance.url), status: 'ok', ms: Date.now() - _t0 });
      return { status: "sucesso", instance: instance.url, data: responseData };
    } catch (err: any) {
      const detail = err.response
        ? `HTTP ${err.response.status}: ${JSON.stringify(err.response.data)}`
        : err.message;
      console.log(`[Integrador] Falha ao replicar para ${instance.url}${urlPath} — ${detail}`);
      addLog({ method, path: urlPath, instance: instance.url, instanceName: getShortName(instance.url), status: 'erro', ms: Date.now() - _t0, error: detail });
      return { status: "erro", instance: instance.url, error: detail };
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
      const result = await forwardGetRequest(categoryName, `/${endpoint}`);
      return res.json(result); // { data: [...], instances: [...] }
    } catch (err: any) {
      return res.status(503).json({ erro: err.message });
    }
  });

  app.get(`/api/${endpoint}/:id`, requireAuth, async (req: Request, res: Response): Promise<any> => {
    try {
      const result = await forwardGetRequest(categoryName, `/${endpoint}/${req.params.id}`);
      return res.json(result.data);
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

app.get("/api/logs", requireAuth, (_req: Request, res: Response) => {
  res.json(logBuffer.slice(0, 200));
});

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
