# Integrador Fight — Documentação Técnica

## O que é este projeto?

O **Integrador Fight** é um API Gateway desenvolvido em Node.js + TypeScript para a disciplina de Sistemas Distribuídos. Ele atua como ponto central de acesso a um conjunto de APIs externas desenvolvidas por outros grupos da turma, todas relacionadas ao domínio de lutas e apostas esportivas.

A ideia central é simples: em vez de o cliente final falar diretamente com cada API, ele fala apenas com o gateway. O gateway resolve autenticação, transforma payloads, replica escritas e consolida leituras — abstraindo toda a complexidade das diferenças entre as APIs.

---

O **Gateway** gerencia **4 categorias**, cada uma com **2 instâncias** (APIs de grupos diferentes):

| Categoria    | Instância 1          | Instância 2        |
|-------------|----------------------|--------------------|
| apostadores | FightAzure (Vercel)  | ApiSD (Render)     |
| lutadores   | LutadoresSD (Render) | NanadeFight (Heroku) |
| lutas       | BettingBeta (Vercel) | Bet3m (Railway)    |
| apostas     | NanaDeBets (IP fixo) | ApostaLutas (Vercel) |

---

## Estratégia de Integração

### Leitura (GET): Merge por ID

Quando o cliente faz um GET (ex: listar lutadores), o gateway:

1. Dispara requests para **todas** as instâncias da categoria em paralelo
2. Aguarda todas responderem (sem cancelar as lentas)
3. Faz um **merge por campo `id`**: se o mesmo registro existir nas duas APIs, os campos são fundidos num único objeto, e o campo `_sources` indica de quais APIs ele veio
4. Retorna também o campo `instances` com o status online/offline de cada API

```
GET /api/lutadores
        │
        ├──▶ LutadoresSD ──▶ [{id:1, nome:"João"}, {id:2, nome:"Pedro"}]
        │
        └──▶ NanadeFight ──▶ [{id:1, nome:"João", apelido:"The One"}, {id:3, nome:"Carlos"}]

Resultado final:
[
  {id:1, nome:"João", apelido:"The One", _sources:["LutadoresSD","NanadeFight"]},
  {id:2, nome:"Pedro", _sources:["LutadoresSD"]},
  {id:3, nome:"Carlos", _sources:["NanadeFight"]}
]
```

Isso garante que o cliente sempre veja o conjunto completo de dados, independentemente de qual API possui cada registro.

### Escrita (POST/PUT/DELETE): Replicação para todas

Quando o cliente faz uma escrita, o gateway:

1. Envia o mesmo dado para **todas** as instâncias em paralelo
2. Retorna um relatório por instância (sucesso ou falha com detalhe do erro)
3. Considera a operação válida se ao menos 1 instância respondeu com sucesso

O cliente vê um toast na tela com o resultado de cada banco, por exemplo:
```
Gravado — 2/2 bancos
✓ BettingBeta — gravado com sucesso
✓ Bet3m — gravado com sucesso
```

---

## Autenticação em Dois Níveis

### Nível 1 — JWT próprio do gateway

O gateway tem seu próprio login em `POST /login`. Existem dois perfis:

- `admin / admin` → acesso ao painel administrativo completo (CRUD de todas as categorias + logs)
- `user / user` → acesso à visão do usuário final (Fight Arena), com fluxo guiado de cadastro → aposta

Todas as rotas `/api/*` exigem o token JWT via `Authorization: Bearer <token>`.

### Nível 2 — Login nas APIs filhas

Cada API filha pode ter seu próprio sistema de autenticação. Antes de cada request, o gateway executa `authenticateWithInstance()`, que faz login na API usando as credenciais armazenadas na configuração da instância e repassa o token no header `Authorization` da request encaminhada.

APIs sem autenticação (campo `user` vazio) recebem a flag `NO_AUTH` e o header de autorização é omitido.

---

## O sistema de flags por instância (`InstanceConfig`)

Cada API do mercado tem suas próprias peculiaridades de contrato. Para lidar com isso sem duplicar código, criamos um sistema de **flags de configuração por instância**:

```typescript
type InstanceConfig = {
  url: string;
  user: string;
  pass: string;
  loginPath?: string;           // caminho do login quando não é /login
  trailingSlash?: boolean;      // adiciona / ao final das URLs
  apiKey?: string;              // envia header X-API-KEY
  useEncryption?: boolean;      // cifra payload com AES+RSA
  snakeCasePayload?: boolean;   // converte camelCase → snake_case no body
  shortLutadorFields?: boolean; // renomeia id_lutador1/2 → lutador1/2
  singleLutadorField?: boolean; // renomeia id_lutador1 → id_lutador
  useRsaChunkResponse?: boolean;// decifra resposta que vem como chunks RSA
  useQueryParams?: boolean;     // envia dados via query string (sem body)
  handshakeEndpoint?: string;   // registra chave pública antes de usar
  nomeIntegrador?: string;      // override do nome usado na assinatura RSA
}
```

Cada flag representa um problema real que encontramos durante a integração:

---

## Camada de Segurança de cada API

### FightAzure (apostadores)
API Node.js padrão, autenticação simples com `usuario/senha`. Nenhuma transformação necessária.

### ApiSD (apostadores)
Framework FastAPI (Python). Exige barra ao final das URLs: `/apostadores/` em vez de `/apostadores`. Resolvido com a flag `trailingSlash: true`.

### LutadoresSD (lutadores)
API sem autenticação. Base URL com `/api` no caminho. Sem transformações necessárias.

### NanadeFight (lutadores)
A API mais complexa do projeto. Implementa **criptografia RSA bidirecional**:

1. **Handshake inicial**: antes de qualquer uso, o gateway envia sua chave pública RSA para o endpoint `/handshake` da API. Isso é feito uma única vez por sessão (cache em `handshakeCache`).
2. **Envio de dados**: escritas são feitas via **query string** em vez de body JSON (flag `useQueryParams`).
3. **Respostas cifradas**: os dados de retorno chegam como um array de strings base64, cada uma sendo um chunk cifrado com a chave pública que enviamos no handshake. O gateway decifra cada chunk com sua chave privada de sessão e reconstrói o JSON.

Para lidar com isso sem expor as chaves entre requests, geramos um **par de chaves efêmero por instância** (`rsaSessionKeys`). Se a decifração falhar (chave expirada ou sessão perdida), o gateway limpa o cache e refaz o handshake automaticamente.

### BettingBeta (lutas)
API com autenticação via assinatura RSA M2M. Cada request inclui os headers:
- `x-api-nome`: nome do integrador
- `x-assinatura`: assinatura SHA-256 da string `nome:rota`, gerada com a chave privada do gateway

A chave pública correspondente foi entregue manualmente ao grupo da BettingBeta.

### Bet3m (lutas)
API Spring Boot (Java). Dois problemas encontrados:

1. **Autenticação por API Key**: exige header `X-API-KEY: bet3M-UENP` em todas as requests (flag `apiKey`).
2. **Campos de lutadores com nome diferente**: espera `lutador1` e `lutador2` no body, enquanto o gateway usa internamente `id_lutador1` e `id_lutador2`. Resolvido com a flag `shortLutadorFields: true`, que aplica a renomeação antes de enviar.

### NanaDeBets (apostas)
API com **criptografia híbrida RSA+AES**:

1. O gateway busca a chave pública da API em `/crypto/public-key` (com cache)
2. Gera uma chave AES-256 aleatória para cada request
3. Cifra o payload JSON com AES-256-CBC
4. Cifra a chave AES com a chave pública RSA da API (OAEP SHA-256)
5. Envia `{ encryptedKey, iv, encryptedData }` com o header `X-Encrypted: true`

### ApostaLutas (apostas)
API FastAPI (Python) com dois requisitos específicos:

1. **Payload em snake_case**: espera `id_apostador`, `id_luta`, etc. O gateway usa camelCase internamente, então a flag `snakeCasePayload: true` aplica a conversão automática antes de enviar.
2. **Campo de lutador singular**: espera `id_lutador` (singular, o lutador apostado para ganhar), enquanto o contrato interno usa `id_lutador1` e `id_lutador2`. A flag `singleLutadorField: true` mapeia `id_lutador1 → id_lutador` e descarta `id_lutador2`.
3. **Login em rota diferente**: usa `/auth/login` em vez do padrão `/login` (flag `loginPath`).

---

## Pipeline de transformação de payload

Toda escrita passa pelo seguinte pipeline em `replicateWriteRequest()`:

```
Payload original (camelCase)
        │
        ▼ se snakeCasePayload
  snake_case via toSnakeCase()
        │
        ▼ se shortLutadorFields
  id_lutador1 → lutador1
  id_lutador2 → lutador2
        │
        ▼ se singleLutadorField
  id_lutador1 → id_lutador
  (remove id_lutador2)
        │
        ▼ se useQueryParams
  body → query string (sem JSON)
        │
        ▼ se useEncryption
  payload → { encryptedKey, iv, encryptedData }
        │
        ▼
  Request enviada à instância
```

---

## Logs de requisições

Toda request encaminhada às APIs (sucesso ou erro) é registrada em um buffer circular em memória via `addLog()`:

```typescript
type LogEntry = {
  id: number;
  ts: string;        // timestamp ISO
  method: string;    // GET, POST, PUT, DELETE
  path: string;      // /apostadores, /lutas/3, etc.
  instance: string;  // URL da instância
  instanceName: string; // nome legível (ex: "Bet3m")
  status: 'ok' | 'erro';
  ms: number;        // tempo de resposta em ms
  error?: string;    // detalhe do erro, se houver
}
```

O buffer mantém no máximo 500 entradas (as mais recentes). O endpoint `GET /api/logs` expõe as últimas 200 para o painel admin.

---

## Interface Web

O gateway entrega sua própria interface em `public/index.html`, com dois modos:

### Painel Admin (`admin/admin`)
- Abas para cada categoria: Apostadores, Lutadores, Lutas, Apostas
- CRUD completo com replicação para todas as instâncias
- Status online/offline de cada API por categoria
- Aba de Logs com histórico de requisições (método, rota, instância, tempo, status)
- Toast central mostrando o resultado da replicação após cada escrita

### Fight Arena (`user/user`)
- Visão focada no fluxo do apostador final
- Painel de status de todas as APIs conectadas
- Cadastro como apostador (salvo em localStorage para persistir entre sessões)
- Cadastro de lutadores e lutas
- Grid de lutas disponíveis com modal para fazer apostas
- Botão "Sair do cadastro" para trocar de apostador sem sair do sistema

---

## Variáveis de ambiente

| Variável | Uso |
|---|---|
| `PORT` | Porta do servidor (padrão: 8080) |
| `JWT_SECRET` | Segredo para assinar tokens JWT |
| `NOME_INTEGRADOR` | Nome usado na assinatura RSA M2M para lutas |
| `APOSTAS_USER` | Usuário para login na API ApostaLutas |
| `APOSTAS_PASS` | Senha para login na API ApostaLutas |

---

## Como rodar

```bash
npm install
npm run dev       # desenvolvimento com ts-node
npm run build     # compila TypeScript
npm start         # produção (node dist/server.js)
```

Acesse `http://localhost:8080` para a interface web.
