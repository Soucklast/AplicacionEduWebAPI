# main.py - API REST CON FIREBASE Y PROXY OLLAMA
# ----------------------------------------------------------------------
# NOTA: ESTE CÓDIGO INCLUYE LOGIN JWT, AI PROXY Y PERSISTENCIA DE CONTENIDO
# ----------------------------------------------------------------------

# ===============================================
# 1. DEPENDENCIAS E INICIALIZACIÓN
# ===============================================

import os
import requests
import firebase_admin
from firebase_admin import credentials, firestore
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer 
from pydantic import BaseModel
from passlib.context import CryptContext
from dotenv import load_dotenv

from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
import hashlib
import hmac

from fastapi.middleware.cors import CORSMiddleware


# Cargar variables de entorno
load_dotenv()

# --- CONFIGURACIÓN DE FIREBASE ---
db = None
try:
    # Intentar usar variables de entorno primero (para Render)
    firebase_project_id = os.getenv("FIREBASE_PROJECT_ID")
    
    if firebase_project_id:
        # Configuración desde variables de entorno
        firebase_creds = {
            "type": os.getenv("FIREBASE_TYPE", "service_account"),
            "project_id": firebase_project_id,
            "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
            "private_key": os.getenv("FIREBASE_PRIVATE_KEY", "").replace('\\n', '\n'),
            "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
            "client_id": os.getenv("FIREBASE_CLIENT_ID"),
            "auth_uri": os.getenv("FIREBASE_AUTH_URI", "https://accounts.google.com/o/oauth2/auth"),
            "token_uri": os.getenv("FIREBASE_TOKEN_URI", "https://oauth2.googleapis.com/token"),
            "auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_CERT_URL", "https://www.googleapis.com/oauth2/v1/certs"),
            "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_CERT_URL"),
            "universe_domain": os.getenv("FIREBASE_UNIVERSE_DOMAIN", "googleapis.com")
        }
        cred = credentials.Certificate(firebase_creds)
        print("🔐 Usando credenciales de Firebase desde variables de entorno")
    else:
        # Fallback: usar archivo firebase.json local
        CREDENTIALS_FILE = "firebase.json"
        cred = credentials.Certificate(CREDENTIALS_FILE)
        print("📄 Usando credenciales de Firebase desde archivo local")
    
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    print("✅ Conexión con Firebase Firestore establecida con éxito.")
except FileNotFoundError:
    db = None 
    print(f"❌ ERROR: No se encontró el archivo de credenciales. La BD no estará funcional.")
except Exception as e:
    db = None
    print(f"❌ ERROR Fatal en Firebase: {e}")

# INICIALIZACIÓN DE FASTAPI
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:4200", 
        "http://127.0.0.1:4200",
        "http://localhost:3000", 
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "https://soucklast.github.io"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Configuración de Seguridad y LLM
pwd_context = CryptContext(schemes=["scrypt"], deprecated="auto")

# Configuración de IA - Soporta Ollama local, Groq cloud o AIML API
AI_PROVIDER = os.getenv("AI_PROVIDER", "ollama")  # "ollama", "groq" o "aiml"
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
AIMLAPI_URL = os.getenv("AIMLAPI_URL", "http://localhost:11434/api/generate")  # Mantener por compatibilidad
AIML_API_KEY = os.getenv("AIML_API_KEY", "")
AIML_API_URL = "https://api.aimlapi.com/chat/completions"
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# --- CONSTANTES DE SEGURIDAD JWT ---
SECRET_KEY = os.getenv("SECRET_KEY", "tu-clave-secreta-super-larga") 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")

# ===============================================
# MODELOS PYDANTIC (ESQUEMAS DE DATOS)
# ===============================================

class AIConsulta(BaseModel):
    """Esquema para la consulta del tutor IA."""
    pregunta: str
    tema_id: str

class UserCreate(BaseModel):
    """Esquema para el registro de nuevos usuarios."""
    email: str
    password: str
    nombre: str
    rol: str = "alumno"  # Por defecto alumno, se puede especificar el rol

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class MateriaCreate(BaseModel):
    """Esquema para crear una nueva Materia."""
    id: str
    nombre: str
    orden: int = 99

class MateriaUpdate(BaseModel):
    """Esquema para actualizar una Materia."""
    nombre: Optional[str] = None
    orden: Optional[int] = None

class UnidadCreate(BaseModel):
    """Esquema para crear una nueva Unidad."""
    id_materia: str
    numero: int
    titulo: str
    descripcion: str

class UnidadUpdate(BaseModel):
    """Esquema para actualizar una Unidad."""
    titulo: Optional[str] = None
    descripcion: Optional[str] = None
    numero: Optional[int] = None

class ContenidoCreate(BaseModel):
    """Esquema para crear contenido de un tema."""
    tema_id: str
    nombre_tema: str
    texto_markdown: str
    id_unidad: str  # Agregar este campo
    id_materia: str  # Agregar este campo
    numero: int = 1  # Agregar este campo
    descripcion: Optional[str] = None

class ContenidoUpdate(BaseModel):
    """Esquema para actualizar contenido."""
    nombre_tema: Optional[str] = None
    texto_markdown: Optional[str] = None
    descripcion: Optional[str] = None
    numero: Optional[int] = None  

class ProgresoCreate(BaseModel):
    """Esquema para registrar progreso del alumno."""
    tema_id: str
    unidad_id: str
    materia_id: str
    completado: bool = True
    puntuacion: Optional[int] = None
    tiempo_dedicado: Optional[int] = None

class TokenData(BaseModel):
    email: Optional[str] = None

# ===============================================
# FUNCIONES DE LÓGICA (CIFRADO Y JWT)
# ===============================================

HASH_SECRET = b'esta_es_la_clave_secreta_del_hash_para_el_equipo_solamente'

def get_password_hash(password: str) -> str:
    """Cifra la contraseña usando HMAC-SHA256."""
    hashed = hmac.new(HASH_SECRET, password.encode('utf-8'), hashlib.sha256)
    return hashed.hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica si la contraseña dada coincide con el hash almacenado."""
    return get_password_hash(plain_password) == hashed_password

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_tema_content(tema_id: str):
    """Lee el contenido didáctico para un tema específico."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    doc_ref = db.collection("Contenidos").document(tema_id)
    doc = doc_ref.get()
    
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Tema de contenido no encontrado: {tema_id}")

    data = doc.to_dict()
    return {
        "nombre_tema": data.get("nombre_tema", "Tema sin título"),
        "texto_markdown": data.get("texto_markdown", "Contenido no disponible."),
        "id": doc.id,
        "id_unidad": data.get("id_unidad", ""),
        "id_materia": data.get("id_materia", ""),
        "numero": data.get("numero", 1),
        "descripcion": data.get("descripcion", "")
    }
    
    
    
# ===============================================
# MODELOS PARA EJERCICIOS
# ===============================================

class EjercicioCreate(BaseModel):
    """Esquema para crear ejercicios."""
    tema_id: str
    enunciado: str
    respuesta_correcta: str
    tipo: str = "multiple_choice"  # multiple_choice, codigo, texto
    opciones: Optional[list] = None
    dificultad: str = "principiante"

class EjercicioUpdate(BaseModel):
    """Esquema para actualizar ejercicios."""
    enunciado: Optional[str] = None
    respuesta_correcta: Optional[str] = None
    tipo: Optional[str] = None
    opciones: Optional[list] = None
    dificultad: Optional[str] = None

class EjercicioRespuesta(BaseModel):
    """Esquema para que alumno responda ejercicio."""
    ejercicio_id: str
    respuesta: str



# ===============================================
# SISTEMA DE AUTENTICACIÓN Y ROLES
# ===============================================

def get_user_by_email(email: str):
    """Busca un usuario en Firebase por email."""
    if db is None:
        return None
    try:
        doc = db.collection("Usuarios").document(email).get()
        if doc.exists:
            return doc.to_dict()
    except Exception:
        return None
    return None

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Decodifica el JWT y devuelve los datos del usuario."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudo validar la credencial",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    
    user = get_user_by_email(email=token_data.email)
    if user is None:
        raise credentials_exception
    
    return user

async def get_current_admin(current_user: dict = Depends(get_current_user)):
    """Verifica que el usuario tenga rol de administrador."""
    if current_user.get("rol") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso Denegado. Se requiere rol de Administrador.",
        )
    return current_user

async def get_current_alumno(current_user: dict = Depends(get_current_user)):
    """Verifica que el usuario tenga rol de alumno."""
    if current_user.get("rol") != "alumno":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso Denegado. Esta funcionalidad es solo para alumnos.",
        )
    return current_user

# ===============================================
# ENDPOINTS PÚBLICOS
# ===============================================

@app.get("/api/v1/saludo")
def test_db_connection():
    """Prueba de conexión con la base de datos."""
    if db is None:
        raise HTTPException(status_code=500, detail="El servidor falló al conectar la BD.")
        
    try:
        test_doc = db.collection("Materias").document("fundamentos_prog").get()
        if test_doc.exists:
            return {"status": "OK", "message": "Servidor y BD conectados.", "data_test": test_doc.to_dict()}
        else:
            return {"status": "BD conectada", "message": "Servidor listo, pero las colecciones de contenido (Materias) aún están vacías."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fallo al leer la BD: {str(e)}")

@app.get("/api/v1/materias")
def get_all_materias():
    """Endpoint público para listar todas las materias disponibles."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        materias_ref = db.collection("Materias").get()
        materias = []
        for doc in materias_ref:
            data = doc.to_dict()
            data['id'] = doc.id
            materias.append(data)
            
        materias.sort(key=lambda x: x.get('orden', 99))
        return materias
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al listar materias: {e}")


@app.get("/api/v1/ejercicios")
def get_all_ejercicios(current_admin: dict = Depends(get_current_admin)):
    """Admin: Obtener todos los ejercicios."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        ejercicios_ref = db.collection("Ejercicios").get()
        ejercicios = []
        for doc in ejercicios_ref:
            data = doc.to_dict()
            data['id'] = doc.id
            ejercicios.append(data)
            
        return ejercicios
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al listar ejercicios: {e}")
    
@app.get("/api/v1/contenidos")
def get_all_contenidos(current_admin: dict = Depends(get_current_admin)):
    """Admin: Obtener todos los contenidos."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        contenidos_ref = db.collection("Contenidos").get()
        contenidos = []
        for doc in contenidos_ref:
            data = doc.to_dict()
            data['id'] = doc.id
            contenidos.append(data)
            
        return contenidos
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al listar contenidos: {e}")
   
    

@app.get("/api/v1/unidades")
def get_all_unidades():
    """Endpoint público para listar todas las unidades."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        unidades_ref = db.collection("Unidades").get()
        unidades = []
        for doc in unidades_ref:
            data = doc.to_dict()
            data['id'] = doc.id
            unidades.append(data)
            
        # Ordenar por materia y luego por número
        unidades.sort(key=lambda x: (x.get('id_materia', ''), x.get('numero', 99)))
        return unidades
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al listar unidades: {e}")

@app.get("/api/v1/materias/{materia_id}/unidades")
def get_unidades_por_materia(materia_id: str):
    """Endpoint público para listar unidades de una materia."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        unidades_ref = db.collection("Unidades").where("id_materia", "==", materia_id).get()
        unidades = []
        for doc in unidades_ref:
            data = doc.to_dict()
            data['id'] = doc.id
            unidades.append(data)
            
        unidades.sort(key=lambda x: x.get('numero', 99))
        return unidades
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al listar unidades: {e}")

@app.get("/api/v1/contenido/tema/{tema_id}")
def get_tema_api(tema_id: str):
    """Ruta pública para obtener lección didáctica de un tema."""
    try:
        contenido = get_tema_content(tema_id)
        return contenido
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener contenido: {e}")

# ===============================================
# ENDPOINTS DE ADMINISTRADOR - CRUD COMPLETO
# ===============================================
# 
# MATERIAS CRUD:
# POST   /api/v1/admin/materias              - Crear materia
# GET    /api/v1/materias                    - Listar todas las materias
# GET    /api/v1/admin/materias              - Listar todas las materias (admin)
# GET    /api/v1/admin/materias/{id}         - Obtener materia por ID
# PUT    /api/v1/admin/materias/{id}         - Actualizar materia
# DELETE /api/v1/admin/materias/{id}         - Eliminar materia
#
# UNIDADES CRUD:
# POST   /api/v1/admin/unidades              - Crear unidad
# GET    /api/v1/unidades                    - Listar todas las unidades
# GET    /api/v1/admin/unidades              - Listar todas las unidades (admin)
# GET    /api/v1/materias/{id}/unidades      - Listar unidades por materia
# GET    /api/v1/admin/unidades/{id}         - Obtener unidad por ID
# PUT    /api/v1/admin/unidades/{id}         - Actualizar unidad
# DELETE /api/v1/admin/unidades/{id}         - Eliminar unidad
#
# CONTENIDOS CRUD:
# POST   /api/v1/admin/contenido             - Crear contenido
# GET    /api/v1/contenidos                  - Listar todos los contenidos (admin)
# GET    /api/v1/admin/contenidos            - Listar contenidos con filtros (admin)
# GET    /api/v1/contenido/tema/{id}         - Obtener contenido por tema
# GET    /api/v1/admin/contenidos/{id}       - Obtener contenido por ID (admin)
# PUT    /api/v1/admin/contenidos/{id}       - Actualizar contenido
# DELETE /api/v1/admin/contenido/{id}        - Eliminar contenido
#
# EJERCICIOS CRUD:
# POST   /api/v1/admin/ejercicios            - Crear ejercicio
# GET    /api/v1/ejercicios                  - Listar todos los ejercicios (admin)
# GET    /api/v1/admin/ejercicios            - Listar todos los ejercicios (admin)
# GET    /api/v1/admin/ejercicios/ejercicio/{id} - Obtener ejercicio por ID
# GET    /api/v1/admin/ejercicios/{tema_id}  - Obtener ejercicios por tema
# PUT    /api/v1/admin/ejercicios/{id}       - Actualizar ejercicio
# DELETE /api/v1/admin/ejercicios/{id}       - Eliminar ejercicio
#
# ENDPOINTS DE BÚSQUEDA Y FILTRADO:
# GET    /api/v1/admin/ejercicios/tipo/{tipo}           - Ejercicios por tipo
# GET    /api/v1/admin/ejercicios/dificultad/{nivel}    - Ejercicios por dificultad
# GET    /api/v1/admin/count/materias                   - Contar materias
# GET    /api/v1/admin/count/unidades                   - Contar unidades
# GET    /api/v1/admin/count/contenidos                 - Contar contenidos
# GET    /api/v1/admin/count/ejercicios                 - Contar ejercicios
# ===============================================


@app.post("/api/v1/admin/materias", status_code=201)
def create_materia_admin(materia: MateriaCreate, current_admin: dict = Depends(get_current_admin)):
    """Admin: Crear nueva materia."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        doc_ref = db.collection("Materias").document(materia.id)
        if doc_ref.get().exists:
            raise HTTPException(status_code=400, detail=f"La Materia con ID '{materia.id}' ya existe.")
            
        db.collection("Materias").document(materia.id).set(materia.dict())
        return {"message": f"Materia '{materia.nombre}' creada exitosamente."}
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear materia: {e}")

@app.post("/api/v1/admin/unidades", status_code=201)
def create_unidad_admin(unidad: UnidadCreate, current_admin: dict = Depends(get_current_admin)):
    """Admin: Crear nueva unidad."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        unidades_existentes = db.collection("Unidades")
        query = unidades_existentes.where("id_materia", "==", unidad.id_materia).where("numero", "==", unidad.numero).limit(1)
        
        if query.get():
            raise HTTPException(status_code=400, detail=f"La Unidad {unidad.numero} en la materia '{unidad.id_materia}' ya existe.")
            
        db.collection("Unidades").add(unidad.dict())
        return {"message": f"Unidad '{unidad.titulo}' creada exitosamente."}
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear unidad: {e}")

@app.post("/api/v1/admin/contenido", status_code=201)
def create_contenido_admin(contenido: ContenidoCreate, current_admin: dict = Depends(get_current_admin)):
    """Admin: Crear contenido para un tema (ahora incluye datos de tema)."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        # Verificar si ya existe contenido para este tema_id
        doc_ref = db.collection("Contenidos").document(contenido.tema_id)
        if doc_ref.get().exists:
            raise HTTPException(status_code=400, detail=f"Ya existe contenido para el tema '{contenido.tema_id}'.")
            
        # Guardar en Contenidos con todos los datos del tema
        contenido_data = contenido.dict()
        db.collection("Contenidos").document(contenido.tema_id).set(contenido_data)
        return {"message": f"Contenido para '{contenido.nombre_tema}' creado exitosamente."}
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear contenido: {e}")


@app.post("/api/v1/admin/ejercicios", status_code=201)
def create_ejercicio_admin(ejercicio: EjercicioCreate, current_admin: dict = Depends(get_current_admin)):
    """Admin: Crear nuevo ejercicio."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        ejercicio_id = f"{ejercicio.tema_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        ejercicio_data = ejercicio.dict()
        ejercicio_data["fecha_creacion"] = datetime.utcnow()
        
        # Verificar que ejercicios de opción múltiple tengan opciones
        if ejercicio_data["tipo"] == "multiple_choice" and (not ejercicio_data.get("opciones") or len(ejercicio_data["opciones"]) < 2):
            raise HTTPException(status_code=400, detail="Los ejercicios de opción múltiple deben tener al menos 2 opciones")
        
        db.collection("Ejercicios").document(ejercicio_id).set(ejercicio_data)
        return {"message": "Ejercicio creado exitosamente", "ejercicio_id": ejercicio_id}
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear ejercicio: {e}")


@app.delete("/api/v1/admin/materias/{materia_id}")
def delete_materia_admin(materia_id: str, current_admin: dict = Depends(get_current_admin)):
    """Admin: Eliminar materia y sus unidades asociadas."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        materia_doc = db.collection("Materias").document(materia_id)
        if not materia_doc.get().exists:
            raise HTTPException(status_code=404, detail=f"Materia '{materia_id}' no encontrada.")
        
        materia_doc.delete()
        
        unidades_ref = db.collection("Unidades").where("id_materia", "==", materia_id).get()
        for doc in unidades_ref:
            doc.reference.delete()
            
        return {"message": f"Materia '{materia_id}' y sus unidades eliminadas exitosamente."}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al eliminar materia: {e}")

@app.delete("/api/v1/admin/unidades/{unidad_id}")
def delete_unidad_admin(unidad_id: str, current_admin: dict = Depends(get_current_admin)):
    """Admin: Eliminar unidad específica."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        unidad_doc = db.collection("Unidades").document(unidad_id)
        if not unidad_doc.get().exists:
            raise HTTPException(status_code=404, detail=f"Unidad '{unidad_id}' no encontrada.")
        
        unidad_doc.delete()
        return {"message": f"Unidad '{unidad_id}' eliminada exitosamente."}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al eliminar unidad: {e}")
    
    
@app.delete("/api/v1/admin/contenido/{tema_id}")
def delete_contenido_admin(tema_id: str, current_admin: dict = Depends(get_current_admin)):
    """Admin: Eliminar contenido específico."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        contenido_doc = db.collection("Contenidos").document(tema_id)
        if not contenido_doc.get().exists:
            raise HTTPException(status_code=404, detail=f"Contenido '{tema_id}' no encontrado.")
        
        contenido_doc.delete()
        return {"message": f"Contenido '{tema_id}' eliminado exitosamente."}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al eliminar contenido: {e}")


@app.delete("/api/v1/admin/contenidos/{tema_id}")
def delete_contenido_admin(tema_id: str, current_admin: dict = Depends(get_current_admin)):
    """Admin: Eliminar contenido específico"""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        # Buscar el contenido por tema_id
        contenidos_ref = db.collection("Contenidos").where("tema_id", "==", tema_id).get()
        
        if not contenidos_ref:
            raise HTTPException(status_code=404, detail=f"Contenido con tema_id '{tema_id}' no encontrado.")
        
        # Eliminar el documento (debería haber solo uno con ese tema_id)
        for doc in contenidos_ref:
            doc.reference.delete()
        
        return {"message": f"Contenido '{tema_id}' eliminado exitosamente."}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al eliminar contenido: {e}")


@app.delete("/api/v1/admin/ejercicios/{ejercicio_id}")
def delete_ejercicio_admin(ejercicio_id: str, current_admin: dict = Depends(get_current_admin)):
    """Admin: Eliminar ejercicio específico."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        ejercicio_doc = db.collection("Ejercicios").document(ejercicio_id)
        if not ejercicio_doc.get().exists:
            raise HTTPException(status_code=404, detail=f"Ejercicio '{ejercicio_id}' no encontrado.")
        
        ejercicio_doc.delete()
        return {"message": f"Ejercicio '{ejercicio_id}' eliminado exitosamente."}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al eliminar ejercicio: {e}")

# ===============================================
# ENDPOINTS CRUD - OPERACIONES DE ACTUALIZACIÓN (PUT)
# ===============================================

@app.put("/api/v1/admin/materias/{materia_id}")
def update_materia_admin(materia_id: str, materia: MateriaUpdate, current_admin: dict = Depends(get_current_admin)):
    """Admin: Actualizar materia existente."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        materia_doc = db.collection("Materias").document(materia_id)
        if not materia_doc.get().exists:
            raise HTTPException(status_code=404, detail=f"Materia '{materia_id}' no encontrada.")
        
        # Solo actualizar campos que no son None
        update_data = {k: v for k, v in materia.dict().items() if v is not None}
        
        if not update_data:
            raise HTTPException(status_code=400, detail="No se proporcionaron datos para actualizar.")
        
        materia_doc.update(update_data)
        return {"message": f"Materia '{materia_id}' actualizada exitosamente."}
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al actualizar materia: {e}")

@app.put("/api/v1/admin/unidades/{unidad_id}")
def update_unidad_admin(unidad_id: str, unidad: UnidadUpdate, current_admin: dict = Depends(get_current_admin)):
    """Admin: Actualizar unidad existente."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        unidad_doc = db.collection("Unidades").document(unidad_id)
        if not unidad_doc.get().exists:
            raise HTTPException(status_code=404, detail=f"Unidad '{unidad_id}' no encontrada.")
        
        update_data = {k: v for k, v in unidad.dict().items() if v is not None}
        
        if not update_data:
            raise HTTPException(status_code=400, detail="No se proporcionaron datos para actualizar.")
        
        unidad_doc.update(update_data)
        return {"message": f"Unidad '{unidad_id}' actualizada exitosamente."}
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al actualizar unidad: {e}")

@app.put("/api/v1/admin/contenidos/{tema_id}")
def update_contenido_admin(tema_id: str, contenido: ContenidoUpdate, current_admin: dict = Depends(get_current_admin)):
    """Admin: Actualizar contenido existente."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        contenido_doc = db.collection("Contenidos").document(tema_id)
        if not contenido_doc.get().exists:
            raise HTTPException(status_code=404, detail=f"Contenido '{tema_id}' no encontrado.")
        
        update_data = {k: v for k, v in contenido.dict().items() if v is not None}
        
        if not update_data:
            raise HTTPException(status_code=400, detail="No se proporcionaron datos para actualizar.")
        
        contenido_doc.update(update_data)
        return {"message": f"Contenido '{tema_id}' actualizado exitosamente."}
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al actualizar contenido: {e}")

@app.put("/api/v1/admin/ejercicios/{ejercicio_id}")
def update_ejercicio_admin(ejercicio_id: str, ejercicio: EjercicioUpdate, current_admin: dict = Depends(get_current_admin)):
    """Admin: Actualizar ejercicio existente."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        ejercicio_doc = db.collection("Ejercicios").document(ejercicio_id)
        if not ejercicio_doc.get().exists:
            raise HTTPException(status_code=404, detail=f"Ejercicio '{ejercicio_id}' no encontrado.")
        
        update_data = {k: v for k, v in ejercicio.dict().items() if v is not None}
        
        if not update_data:
            raise HTTPException(status_code=400, detail="No se proporcionaron datos para actualizar.")
        
        # Validar tipo de ejercicio si se está actualizando
        if "tipo" in update_data and update_data["tipo"] == "multiple_choice":
            ejercicio_actual = ejercicio_doc.get().to_dict()
            opciones_actuales = ejercicio_actual.get("opciones", [])
            opciones_nuevas = update_data.get("opciones", opciones_actuales)
            
            if not opciones_nuevas or len(opciones_nuevas) < 2:
                raise HTTPException(status_code=400, detail="Los ejercicios de opción múltiple deben tener al menos 2 opciones")
        
        ejercicio_doc.update(update_data)
        return {"message": f"Ejercicio '{ejercicio_id}' actualizado exitosamente."}
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al actualizar ejercicio: {e}")

# ===============================================
# ENDPOINTS CRUD - OPERACIONES DE LECTURA INDIVIDUAL (GET BY ID)
# ===============================================

@app.get("/api/v1/admin/materias/{materia_id}")
def get_materia_by_id_admin(materia_id: str, current_admin: dict = Depends(get_current_admin)):
    """Admin: Obtener materia específica por ID."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        materia_doc = db.collection("Materias").document(materia_id)
        doc = materia_doc.get()
        
        if not doc.exists:
            raise HTTPException(status_code=404, detail=f"Materia '{materia_id}' no encontrada.")
        
        data = doc.to_dict()
        data['id'] = doc.id
        return data
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener materia: {e}")

@app.get("/api/v1/admin/unidades/{unidad_id}")
def get_unidad_by_id_admin(unidad_id: str, current_admin: dict = Depends(get_current_admin)):
    """Admin: Obtener unidad específica por ID."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        unidad_doc = db.collection("Unidades").document(unidad_id)
        doc = unidad_doc.get()
        
        if not doc.exists:
            raise HTTPException(status_code=404, detail=f"Unidad '{unidad_id}' no encontrada.")
        
        data = doc.to_dict()
        data['id'] = doc.id
        return data
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener unidad: {e}")

@app.get("/api/v1/admin/contenidos/{tema_id}")
def get_contenido_by_id_admin(tema_id: str, current_admin: dict = Depends(get_current_admin)):
    """Admin: Obtener contenido específico por tema_id."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        contenido_doc = db.collection("Contenidos").document(tema_id)
        doc = contenido_doc.get()
        
        if not doc.exists:
            raise HTTPException(status_code=404, detail=f"Contenido '{tema_id}' no encontrado.")
        
        data = doc.to_dict()
        data['id'] = doc.id
        return data
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener contenido: {e}")

@app.get("/api/v1/admin/ejercicios/ejercicio/{ejercicio_id}")
def get_ejercicio_by_id_admin(ejercicio_id: str, current_admin: dict = Depends(get_current_admin)):
    """Admin: Obtener ejercicio específico por ID."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        ejercicio_doc = db.collection("Ejercicios").document(ejercicio_id)
        doc = ejercicio_doc.get()
        
        if not doc.exists:
            raise HTTPException(status_code=404, detail=f"Ejercicio '{ejercicio_id}' no encontrado.")
        
        data = doc.to_dict()
        data['id'] = doc.id
        return data
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener ejercicio: {e}")




# ===============================================
# ENDPOINTS DE EJERCICIOS (ADMIN)
# ===============================================

def create_ejercicio_admin(ejercicio: EjercicioCreate, current_admin: dict = Depends(get_current_admin)):
    """Admin: Crear nuevo ejercicio."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        ejercicio_id = f"{ejercicio.tema_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        ejercicio_data = ejercicio.dict()
        ejercicio_data["fecha_creacion"] = datetime.utcnow()
        
        db.collection("Ejercicios").document(ejercicio_id).set(ejercicio_data)
        return {"message": "Ejercicio creado exitosamente", "ejercicio_id": ejercicio_id}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear ejercicio: {e}")

@app.get("/api/v1/admin/estadisticas")
def get_estadisticas_admin(current_admin: dict = Depends(get_current_admin)):
    """Admin: Ver estadísticas del sistema"""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        # Usuarios totales
        usuarios_ref = db.collection("Usuarios").get()
        total_usuarios = len(usuarios_ref)
        
        # Administradores
        admins_ref = db.collection("Usuarios").where("rol", "==", "admin").get()
        total_admins = len(admins_ref)
        
        # Materias
        materias_ref = db.collection("Materias").get()
        total_materias = len(materias_ref)
        
        # Unidades (contar todas)
        unidades_ref = db.collection("Unidades").get()
        total_unidades = len(unidades_ref)
        
        # Contenidos
        contenidos_ref = db.collection("Contenidos").get()
        total_contenidos = len(contenidos_ref)
        
        # Ejercicios
        ejercicios_ref = db.collection("Ejercicios").get()
        total_ejercicios = len(ejercicios_ref)
        
        return {
            "total_usuarios": total_usuarios,
            "total_admins": total_admins,
            "total_materias": total_materias,
            "total_unidades": total_unidades,
            "total_contenidos": total_contenidos,
            "total_ejercicios": total_ejercicios
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener estadísticas: {e}")

@app.get("/api/v1/admin/ejercicios")
def get_all_ejercicios_admin(current_admin: dict = Depends(get_current_admin)):
    """Admin: Obtener todos los ejercicios"""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        ejercicios_ref = db.collection("Ejercicios").get()
        
        ejercicios = []
        for doc in ejercicios_ref:
            ejercicio_data = doc.to_dict()
            ejercicio_data['id'] = doc.id  # Agregar el ID del documento
            ejercicios.append(ejercicio_data)
        
        return ejercicios
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener ejercicios: {e}")
    
    
@app.get("/api/v1/admin/ejercicios/{tema_id}")
def get_ejercicios_por_tema_admin(tema_id: str, current_admin: dict = Depends(get_current_admin)):
    """Admin: Ver ejercicios de un tema específico."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        ejercicios_ref = db.collection("Ejercicios").where("tema_id", "==", tema_id).get()
        
        ejercicios = []
        for doc in ejercicios_ref:
            data = doc.to_dict()
            data['id'] = doc.id
            ejercicios.append(data)
            
        return ejercicios
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener ejercicios: {e}")


# ===============================================
# ENDPOINT MEJORADO PARA CONTENIDOS ADMIN (CON FILTROS)
# ===============================================

@app.get("/api/v1/admin/contenidos")
def get_all_contenidos_admin(
    unidad_id: Optional[str] = None,
    materia_id: Optional[str] = None,
    current_admin: dict = Depends(get_current_admin)
):
    """Admin: Obtener todos los contenidos o filtrar por unidad/materia."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        # Base query
        if unidad_id:
            # Filtrar por unidad
            contenidos_ref = db.collection("Contenidos").where("id_unidad", "==", unidad_id).get()
        elif materia_id:
            # Filtrar por materia
            contenidos_ref = db.collection("Contenidos").where("id_materia", "==", materia_id).get()
        else:
            # Obtener todos
            contenidos_ref = db.collection("Contenidos").get()
        
        contenidos = []
        for doc in contenidos_ref:
            contenido_data = doc.to_dict()
            contenido_data['id'] = doc.id
            contenidos.append(contenido_data)
        
        # Ordenar por número si es una unidad específica
        if unidad_id:
            contenidos.sort(key=lambda x: x.get('numero', 99))
        
        return contenidos
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener contenidos: {e}")

# ===============================================
# ENDPOINTS ADICIONALES PARA BÚSQUEDA Y FILTRADO
# ===============================================

@app.get("/api/v1/admin/materias")
def get_all_materias_admin(current_admin: dict = Depends(get_current_admin)):
    """Admin: Obtener todas las materias."""
    return get_all_materias()

@app.get("/api/v1/admin/unidades")
def get_all_unidades_admin(current_admin: dict = Depends(get_current_admin)):
    """Admin: Obtener todas las unidades."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        unidades_ref = db.collection("Unidades").get()
        unidades = []
        for doc in unidades_ref:
            data = doc.to_dict()
            data['id'] = doc.id
            unidades.append(data)
            
        unidades.sort(key=lambda x: (x.get('id_materia', ''), x.get('numero', 99)))
        return unidades
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al listar unidades: {e}")

@app.get("/api/v1/admin/unidades/materia/{materia_id}")
def get_unidades_por_materia_admin(materia_id: str, current_admin: dict = Depends(get_current_admin)):
    """Admin: Obtener unidades de una materia específica."""
    return get_unidades_por_materia(materia_id)

@app.get("/api/v1/admin/ejercicios/tema/{tema_id}")
def get_ejercicios_por_tema_admin_direct(tema_id: str, current_admin: dict = Depends(get_current_admin)):
    """Admin: Obtener ejercicios de un tema específico."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        ejercicios_ref = db.collection("Ejercicios").where("tema_id", "==", tema_id).get()
        ejercicios = []
        for doc in ejercicios_ref:
            data = doc.to_dict()
            data['id'] = doc.id
            ejercicios.append(data)
            
        return ejercicios
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener ejercicios: {e}")

@app.get("/api/v1/admin/ejercicios/tipo/{tipo}")
def get_ejercicios_por_tipo_admin(tipo: str, current_admin: dict = Depends(get_current_admin)):
    """Admin: Obtener ejercicios por tipo (multiple_choice, codigo, texto)."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        ejercicios_ref = db.collection("Ejercicios").where("tipo", "==", tipo).get()
        ejercicios = []
        for doc in ejercicios_ref:
            data = doc.to_dict()
            data['id'] = doc.id
            ejercicios.append(data)
            
        return ejercicios
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener ejercicios por tipo: {e}")

@app.get("/api/v1/admin/ejercicios/dificultad/{dificultad}")
def get_ejercicios_por_dificultad_admin(dificultad: str, current_admin: dict = Depends(get_current_admin)):
    """Admin: Obtener ejercicios por dificultad."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        ejercicios_ref = db.collection("Ejercicios").where("dificultad", "==", dificultad).get()
        ejercicios = []
        for doc in ejercicios_ref:
            data = doc.to_dict()
            data['id'] = doc.id
            ejercicios.append(data)
            
        return ejercicios
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener ejercicios por dificultad: {e}")

# ===============================================
# ENDPOINTS DE CONTEO (ÚTILES PARA ESTADÍSTICAS)
# ===============================================

@app.get("/api/v1/admin/count/materias")
def count_materias_admin(current_admin: dict = Depends(get_current_admin)):
    """Admin: Contar total de materias."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        materias_ref = db.collection("Materias").get()
        return {"total_materias": len(materias_ref)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al contar materias: {e}")

@app.get("/api/v1/admin/count/unidades")
def count_unidades_admin(materia_id: Optional[str] = None, current_admin: dict = Depends(get_current_admin)):
    """Admin: Contar unidades (total o por materia)."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        if materia_id:
            unidades_ref = db.collection("Unidades").where("id_materia", "==", materia_id).get()
        else:
            unidades_ref = db.collection("Unidades").get()
        
        return {"total_unidades": len(unidades_ref), "materia_id": materia_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al contar unidades: {e}")

@app.get("/api/v1/admin/count/contenidos")
def count_contenidos_admin(
    unidad_id: Optional[str] = None,
    materia_id: Optional[str] = None,
    current_admin: dict = Depends(get_current_admin)
):
    """Admin: Contar contenidos (total, por unidad o por materia)."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        if unidad_id:
            contenidos_ref = db.collection("Contenidos").where("id_unidad", "==", unidad_id).get()
        elif materia_id:
            contenidos_ref = db.collection("Contenidos").where("id_materia", "==", materia_id).get()
        else:
            contenidos_ref = db.collection("Contenidos").get()
        
        return {
            "total_contenidos": len(contenidos_ref),
            "unidad_id": unidad_id,
            "materia_id": materia_id
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al contar contenidos: {e}")

@app.get("/api/v1/admin/count/ejercicios")
def count_ejercicios_admin(
    tema_id: Optional[str] = None,
    tipo: Optional[str] = None,
    dificultad: Optional[str] = None,
    current_admin: dict = Depends(get_current_admin)
):
    """Admin: Contar ejercicios con filtros opcionales."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        ejercicios_ref = db.collection("Ejercicios")
        
        if tema_id:
            ejercicios_ref = ejercicios_ref.where("tema_id", "==", tema_id)
        if tipo:
            ejercicios_ref = ejercicios_ref.where("tipo", "==", tipo)
        if dificultad:
            ejercicios_ref = ejercicios_ref.where("dificultad", "==", dificultad)
        
        ejercicios = ejercicios_ref.get()
        
        return {
            "total_ejercicios": len(ejercicios),
            "tema_id": tema_id,
            "tipo": tipo,
            "dificultad": dificultad
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al contar ejercicios: {e}")


# ===============================================
# MODELOS PARA EJERCICIOS (REPETIDO PARA CLARIDAD)
# ===============================================

class EjercicioCreate(BaseModel):
    """Esquema para crear ejercicios."""
    tema_id: str
    enunciado: str
    respuesta_correcta: str
    tipo: str = "multiple_choice"  # multiple_choice, codigo, texto
    opciones: Optional[list] = None
    dificultad: str = "principiante"

class EjercicioUpdate(BaseModel):
    """Esquema para actualizar ejercicios."""
    enunciado: Optional[str] = None
    respuesta_correcta: Optional[str] = None
    tipo: Optional[str] = None
    opciones: Optional[list] = None
    dificultad: Optional[str] = None

class EjercicioRespuesta(BaseModel):
    """Esquema para que alumno responda ejercicio."""
    ejercicio_id: str
    respuesta: str





# ===============================================
# ENDPOINTS DE EJERCICIOS (ALUMNO)
# ===============================================

@app.get("/api/v1/alumno/ejercicios/{tema_id}")
def get_ejercicios_por_tema_alumno(tema_id: str, user: dict = Depends(get_current_alumno)):
    """Alumno: Obtener ejercicios de un tema (sin respuestas correctas)."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        ejercicios_ref = db.collection("Ejercicios").where("tema_id", "==", tema_id).get()
        
        ejercicios = []
        for doc in ejercicios_ref:
            data = doc.to_dict()
            # No enviar la respuesta correcta al alumno
            if 'respuesta_correcta' in data:
                del data['respuesta_correcta']
            data['id'] = doc.id
            ejercicios.append(data)
            
        return ejercicios
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener ejercicios: {e}")

# ===============================================
#CORRECCION CON IA 
# ===============================================
# --- RUTA DE CORRECCIÓN INTELIGENTE (MEJORADA CON RETROALIMENTACIÓN REAL) ---

@app.post("/api/v1/alumno/corregir_ia", status_code=status.HTTP_200_OK)
def corregir_ejercicio_ia(respuesta: EjercicioRespuesta, user: dict = Depends(get_current_alumno)):
    """Alumno: Envía una respuesta abierta. La IA la compara con la solución ideal."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")

    try:
        # 1. Obtener datos (Ejercicio, Solución)
        ejercicio_doc = db.collection("Ejercicios").document(respuesta.ejercicio_id).get()
        if not ejercicio_doc.exists:
            raise HTTPException(status_code=404, detail="Ejercicio no encontrado")
        
        ejercicio_data = ejercicio_doc.to_dict()
        respuesta_correcta_oficial = ejercicio_data.get("respuesta_correcta", "Solución no definida.")
        enunciado = ejercicio_data.get("enunciado", "")
        
        # 2. PROMPT MEJORADO - Enfocado en dar retroalimentación educativa
        prompt_correccion = f"""
Eres un tutor de programación. Un alumno respondió a esta pregunta:

Pregunta: {enunciado}

El alumno respondió: "{respuesta.respuesta}"

La respuesta ideal es: "{respuesta_correcta_oficial}"

Proporciona retroalimentación educativa:
- Si la respuesta es correcta: "¡Correcto! [Explica por qué está bien y refuerza el concepto]"
- Si la respuesta es incorrecta: "¡Incorrecto! [Señala el error y explica el concepto correcto]"

Sé claro, amable y educativo. Ayuda al alumno a entender el concepto.
"""

        # 3. Llamar a IA (AIML API, Groq o Ollama)
        if AI_PROVIDER == "aiml" and AIML_API_KEY:
            headers = {
                "Authorization": f"Bearer {AIML_API_KEY}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": "deepseek/deepseek-chat",
                "messages": [
                    {"role": "system", "content": "Eres un tutor de programación."},
                    {"role": "user", "content": prompt_correccion}
                ],
                "temperature": 0.3,
                "max_tokens": 300
            }
            response = requests.post(AIML_API_URL, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            correccion_texto = response.json()["choices"][0]["message"]["content"].strip()
        elif AI_PROVIDER == "groq" and GROQ_API_KEY:
            headers = {
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": "mixtral-8x7b-32768",
                "messages": [
                    {"role": "system", "content": "Eres un tutor de programación."},
                    {"role": "user", "content": prompt_correccion}
                ],
                "temperature": 0.3,
                "max_tokens": 300
            }
            response = requests.post(GROQ_API_URL, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            correccion_texto = response.json()["choices"][0]["message"]["content"].strip()
        else:
            payload = {
                "model": "tinyllama", 
                "prompt": prompt_correccion, 
                "stream": False, 
                "options": {
                    "temperature": 0.3,
                    "top_p": 0.9,
                    "num_predict": 200
                }
            }
            response = requests.post(OLLAMA_URL if 'OLLAMA_URL' in dir() else AIMLAPI_URL, json=payload, timeout=60)
            response.raise_for_status()
            correccion_texto = response.json().get("response", "Error al obtener corrección de IA").strip()
        
        # 4. Procesar y limpiar la respuesta
        correccion_limpia = procesar_retroalimentacion(correccion_texto, respuesta.respuesta, respuesta_correcta_oficial)
        
        # 5. Determinar si es correcta (lógica mejorada)
        es_correcta = determinar_si_es_correcta(respuesta.respuesta, respuesta_correcta_oficial, correccion_limpia)
        
        return {
            "es_correcta": es_correcta,
            "puntuacion": 100 if es_correcta else 0,
            "retroalimentacion": correccion_limpia,
            "explicacion_adicional": "Evaluación realizada por el tutor IA."
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al procesar la corrección de IA: {e}")

def procesar_retroalimentacion(texto_ia, respuesta_alumno, respuesta_correcta):
    """Procesa y mejora la retroalimentación de la IA."""
    
    # Si la IA no dio una respuesta útil, crear una por defecto
    if not texto_ia or len(texto_ia.strip()) < 10:
        if respuesta_alumno.lower().strip() == respuesta_correcta.lower().strip():
            return f"¡Correcto! '{respuesta_alumno}' es la respuesta adecuada. Has comprendido bien el concepto."
        else:
            return f"¡Incorrecto! La respuesta correcta es: '{respuesta_correcta}'. Tu respuesta fue: '{respuesta_alumno}'. Sigue practicando."
    
    # Limpiar texto repetitivo
    lineas = texto_ia.split('\n')
    lineas_limpias = []
    
    for linea in lineas:
        linea_limpia = linea.strip()
        # Remover líneas que son solo repeticiones del prompt
        if any(patron in linea_limpia.lower() for patron in [
            'pregunta:', 'el alumno respondió:', 'la respuesta ideal es:', 
            'proporciona retroalimentación', 'eres un tutor'
        ]):
            continue
        if linea_limpia and len(linea_limpia) > 5:
            lineas_limpias.append(linea_limpia)
    
    resultado = ' '.join(lineas_limpias)
    
    # Asegurar que tenga un formato adecuado
    if not resultado.startswith('¡Correcto!') and not resultado.startswith('¡Incorrecto!'):
        if respuesta_alumno.lower().strip() == respuesta_correcta.lower().strip():
            resultado = f"¡Correcto! {resultado}"
        else:
            resultado = f"¡Incorrecto! {resultado}"
    
    return resultado

def determinar_si_es_correcta(respuesta_alumno, respuesta_correcta, retroalimentacion):
    """Determina si la respuesta es correcta usando múltiples criterios."""
    
    # 1. Comparación directa (case-insensitive)
    if respuesta_alumno.lower().strip() == respuesta_correcta.lower().strip():
        return True
    
    # 2. Basado en la retroalimentación de la IA
    if 'correcto' in retroalimentacion.lower() and 'incorrecto' not in retroalimentacion.lower():
        return True
    if 'incorrecto' in retroalimentacion.lower():
        return False
    
    # 3. Comparación de similitud básica
    palabras_alumno = set(respuesta_alumno.lower().split())
    palabras_correcta = set(respuesta_correcta.lower().split())
    similitud = len(palabras_alumno.intersection(palabras_correcta)) / len(palabras_correcta)
    
    return similitud > 0.7  # 70% de similitud


@app.post("/api/v1/alumno/ejercicios/verificar")
def verificar_respuesta_ejercicio(respuesta: EjercicioRespuesta, user: dict = Depends(get_current_alumno)):
    """Alumno: Verificar si su respuesta es correcta."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        # Obtener el ejercicio
        ejercicio_doc = db.collection("Ejercicios").document(respuesta.ejercicio_id).get()
        
        if not ejercicio_doc.exists:
            raise HTTPException(status_code=404, detail="Ejercicio no encontrado")
        
        ejercicio_data = ejercicio_doc.to_dict()
        respuesta_correcta = ejercicio_data.get("respuesta_correcta", "")
        
        # Verificar si la respuesta es correcta
        es_correcta = respuesta.respuesta.strip().lower() == respuesta_correcta.strip().lower()
        
        return {
            "es_correcta": es_correcta,
            "respuesta_correcta": respuesta_correcta if not es_correcta else None,
            "mensaje": "¡Correcto!" if es_correcta else "Respuesta incorrecta. Intenta nuevamente."
        }
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al verificar respuesta: {e}")














# ===============================================
# ENDPOINTS DE ALUMNO
# ===============================================

@app.get("/api/v1/alumno/materias")
def get_materias_alumno(user: dict = Depends(get_current_alumno)):
    """Alumno: Ver todas las materias disponibles."""
    return get_all_materias()

@app.get("/api/v1/alumno/materias/{materia_id}/unidades")
def get_unidades_alumno(materia_id: str, user: dict = Depends(get_current_alumno)):
    """Alumno: Ver unidades de una materia específica."""
    return get_unidades_por_materia(materia_id)

@app.get("/api/v1/alumno/unidades/{unidad_id}/temas")
def get_temas_alumno(unidad_id: str, user: dict = Depends(get_current_alumno)):
    """Alumno: Ver temas de una unidad específica."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        temas_ref = db.collection("Temas").where("id_unidad", "==", unidad_id).get()
        temas = []
        for doc in temas_ref:
            data = doc.to_dict()
            data['id'] = doc.id
            temas.append(data)
            
        temas.sort(key=lambda x: x.get('numero', 99))
        return temas
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al listar temas: {e}")

@app.get("/api/v1/alumno/contenidos")
def get_contenidos_alumno(user: dict = Depends(get_current_alumno)):
    """Alumno: Obtener todos los contenidos disponibles."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        contenidos_ref = db.collection("Contenidos").get()
        contenidos = []
        for doc in contenidos_ref:
            data = doc.to_dict()
            data['id'] = doc.id
            contenidos.append(data)
            
        return contenidos
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al listar contenidos: {e}")

@app.get("/api/v1/alumno/contenidos/unidad/{unidad_id}")
def get_contenidos_por_unidad_alumno(unidad_id: str, user: dict = Depends(get_current_alumno)):
    """Alumno: Obtener contenidos por unidad."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        contenidos_ref = db.collection("Contenidos").where("id_unidad", "==", unidad_id).get()
        contenidos = []
        for doc in contenidos_ref:
            data = doc.to_dict()
            data['id'] = doc.id
            contenidos.append(data)
            
        contenidos.sort(key=lambda x: x.get('numero', 99))
        return contenidos
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al listar contenidos: {e}")
    
    
@app.get("/api/v1/alumno/contenido/tema/{tema_id}")
def get_contenido_alumno(tema_id: str, user: dict = Depends(get_current_alumno)):
    """Alumno: Obtener contenido de un tema específico."""
    return get_tema_api(tema_id)

@app.post("/api/v1/alumno/progreso", status_code=201)
def registrar_progreso_alumno(progreso: ProgresoCreate, user: dict = Depends(get_current_alumno)):
    """Alumno: Registrar progreso en un tema."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        progreso_data = progreso.dict()
        progreso_data["user_email"] = user["email"]
        progreso_data["fecha_completado"] = datetime.utcnow()
        
        progreso_id = f"{user['email']}_{progreso.tema_id}"
        db.collection("ProgresoAlumnos").document(progreso_id).set(progreso_data)
        
        return {"message": "Progreso registrado exitosamente"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al registrar progreso: {e}")


@app.post("/api/v1/alumno/progreso/unidad")
def registrar_progreso_unidad(progreso: ProgresoCreate, user: dict = Depends(get_current_alumno)):
    """Alumno: Registrar progreso de una unidad completa."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        progreso_data = progreso.dict()
        progreso_data["user_email"] = user["email"]
        progreso_data["fecha_completado"] = datetime.utcnow()
        progreso_data["tipo"] = "unidad_completada"
        
        progreso_id = f"{user['email']}_unidad_{progreso.unidad_id}"
        db.collection("ProgresoAlumnos").document(progreso_id).set(progreso_data)
        
        return {"message": "Progreso de unidad registrado exitosamente"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al registrar progreso: {e}")

@app.get("/api/v1/alumno/mi-progreso")
def get_mi_progreso_alumno(user: dict = Depends(get_current_alumno)):
    """Alumno: Ver mi progreso personal."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    try:
        progreso_ref = db.collection("ProgresoAlumnos").where("user_email", "==", user["email"]).get()
        
        progreso = []
        for doc in progreso_ref:
            data = doc.to_dict()
            data['id'] = doc.id
            progreso.append(data)
            
        return progreso
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener progreso: {e}")

@app.post("/api/v1/alumno/ai/consulta")
def consulta_ai_alumno(consulta: AIConsulta, user: dict = Depends(get_current_alumno)):
    """Alumno: Consultar al tutor IA."""
    return ai_query_proxy(consulta)

# ===============================================
# MÓDULO DE INTELIGENCIA ARTIFICIAL
# ===============================================

@app.post("/api/v1/ai/consulta")
def ai_query_proxy(consulta: AIConsulta):
    """Proxy para el LLM (Ollama)."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")

    try:
        contenido_response = get_tema_content(consulta.tema_id) 
        contexto = contenido_response.get("texto_markdown", "Contenido no disponible.")
        
        # PROMPT MEJORADO - más específico y con mejores instrucciones
        prompt_final = f"""
        Eres CodeMentor, un tutor de programación y tecnología experto y amable.
        
        INSTRUCCIONES CRÍTICAS:
        - Responde ÚNICAMENTE en español, no quiero otro idioma.
        - Usa un lenguaje sencillo, apto para principiantes.
        - Sé claro, conciso pero completo
        - Usa ejemplos cuando sea útil
        - Explica conceptos técnicos de manera sencilla
        - Mantén un tono amigable y alentador
        - Estructura tu respuesta en párrafos bien organizados
        - Si el concepto es complejo, usa analogías simples
        - No incluyas listas numeradas ni viñetas
        - No repitas las instrucciones en tu respuesta, es decir, no incluyas el prompt en la respuesta.
        
        
        CONTEXTO DE LA LECCIÓN (usa esto como base):
        {contexto}
        
        PREGUNTA DEL ALUMNO:
        "{consulta.pregunta}"
        
        Por favor, proporciona una respuesta educativa y útil basada en el contexto:
        """

        # Decidir qué proveedor usar
        print(f"🤖 Usando proveedor de IA: {AI_PROVIDER}")
        
        if AI_PROVIDER == "aiml" and AIML_API_KEY:
            # Usar AIML API (cloud) - Compatible con OpenAI
            print(f"🔑 API Key presente: {bool(AIML_API_KEY)}")
            headers = {
                "Authorization": f"Bearer {AIML_API_KEY}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": "deepseek/deepseek-chat",  # DeepSeek V3 - Modelo potente
                "messages": [
                    {"role": "system", "content": "Eres CodeMentor, un tutor de programación."},
                    {"role": "user", "content": prompt_final}
                ],
                "temperature": 0.2,
                "max_tokens": 500
            }
            print(f"📡 Enviando petición a: {AIML_API_URL}")
            response = requests.post(AIML_API_URL, json=payload, headers=headers, timeout=30)
            print(f"✅ Status code: {response.status_code}")
            response.raise_for_status()
            texto_generado = response.json()["choices"][0]["message"]["content"].strip()
        elif AI_PROVIDER == "groq" and GROQ_API_KEY:
            # Usar Groq (cloud)
            headers = {
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": "mixtral-8x7b-32768",
                "messages": [
                    {"role": "system", "content": "Eres CodeMentor, un tutor de programación."},
                    {"role": "user", "content": prompt_final}
                ],
                "temperature": 0.2,
                "max_tokens": 500
            }
            response = requests.post(GROQ_API_URL, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            texto_generado = response.json()["choices"][0]["message"]["content"].strip()
        else:
            # Usar Ollama (local)
            payload = {
                "model": "tinyllama",
                "prompt": prompt_final, 
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "top_p": 0.9,
                    "top_k": 40
                }
            }
            response = requests.post(OLLAMA_URL if 'OLLAMA_URL' in dir() else AIMLAPI_URL, json=payload, timeout=60)
            response.raise_for_status()
            texto_generado = response.json().get("response", "Error al obtener texto de IA.").strip()
        
        # Limpiar y formatear la respuesta
        respuesta_limpia = limpiar_respuesta_ia(texto_generado)
        
        return {
            "respuesta": respuesta_limpia,
            "contexto_usado_del_tema": consulta.tema_id,
            "provider": AI_PROVIDER
        }

    except requests.exceptions.Timeout:
        print("❌ Error: Timeout al conectar con IA")
        raise HTTPException(status_code=504, detail="La IA tardó demasiado en responder. Intenta de nuevo.")
    except requests.exceptions.HTTPError as e:
        print(f"❌ Error HTTP de IA: {e.response.status_code} - {e.response.text}")
        raise HTTPException(status_code=503, detail=f"Error de la API de IA: {e.response.text}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error de conexión con IA: {str(e)}")
        raise HTTPException(status_code=503, detail=f"No se pudo conectar con el servicio de IA: {str(e)}")
    except KeyError as e:
        print(f"❌ Error al procesar respuesta de IA: {e}")
        raise HTTPException(status_code=500, detail="La IA devolvió una respuesta en formato inesperado")
    except Exception as e:
        print(f"❌ Error inesperado: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error interno al procesar la consulta: {str(e)}")
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno al procesar la consulta: {e}")

# Función auxiliar para limpiar la respuesta
def limpiar_respuesta_ia(texto):
    """Limpia y formatea la respuesta de la IA."""
    # Remover repeticiones del prompt
    lineas = texto.split('\n')
    lineas_limpias = []
    
    for linea in lineas:
        # Saltar líneas que son repeticiones de instrucciones
        if any(palabra in linea.lower() for palabra in ['instrucciones', 'contexto', 'pregunta del alumno', 'por favor']):
            continue
        # Saltar líneas vacías al inicio
        if not lineas_limpias and not linea.strip():
            continue
        lineas_limpias.append(linea)
    
    texto_limpio = '\n'.join(lineas_limpias).strip()
    
    # Si la respuesta es muy corta, intentar mejorarla
    if len(texto_limpio.split()) < 10:
        texto_limpio = f"La web se refiere a la World Wide Web (WWW), que es un sistema de documentos interconectados accesibles a través de Internet. {texto_limpio}"
    
    return texto_limpio
# ===============================================
# MÓDULO DE AUTENTICACIÓN
# ===============================================

@app.post("/api/v1/auth/register", status_code=201)
def register_user(user: UserCreate):
    """Registra un nuevo usuario."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")

    try:
        user_doc = db.collection("Usuarios").document(user.email).get()
        if user_doc.exists:
            raise HTTPException(status_code=400, detail="El email ya está registrado.")
            
        hashed_password = get_password_hash(user.password)
        
        user_data = {
            "email": user.email,
            "nombre": user.nombre,
            "hashed_password": hashed_password,
            "rol": user.rol  # Ahora usa el rol del request
        }
        
        db.collection("Usuarios").document(user.email).set(user_data)
        return {"message": "Usuario registrado exitosamente."}

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno al registrar usuario: {e}")

@app.post("/api/v1/auth/login", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Verifica credenciales y devuelve un Token JWT."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    
    user_doc = db.collection("Usuarios").document(form_data.username).get() 
    
    if not user_doc.exists:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas: Usuario no encontrado.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_data = user_doc.to_dict()
    
    if not verify_password(form_data.password, user_data["hashed_password"]): 
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas: Contraseña inválida.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_data["email"], "user_id": user_doc.id, "rol": user_data["rol"]}, 
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/api/v1/admin/usuarios")
def get_admin_users(current_admin: dict = Depends(get_current_admin)):
    """Admin: Listar todos los usuarios con rol 'admin'."""
    if db is None:
        raise HTTPException(status_code=500, detail="La Base de Datos no está conectada.")
    try:
        admins_ref = db.collection("Usuarios").where("rol", "==", "admin").get()
        admins = []
        for doc in admins_ref:
            user = doc.to_dict()
            user['id'] = doc.id
            # Remover campo sensible antes de devolver
            user.pop('hashed_password', None)
            admins.append(user)
        return admins
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al listar administradores: {e}")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)