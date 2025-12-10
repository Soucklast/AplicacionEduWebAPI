"""
Script para probar la funcionalidad completa de IA
Prueba tanto la configuración como las llamadas reales a la API
"""

import os
import requests
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

def verificar_configuracion():
    """Verifica que las variables de entorno estén configuradas"""
    print("\n" + "="*60)
    print("VERIFICANDO CONFIGURACIÓN")
    print("="*60)
    
    ai_provider = os.getenv("AI_PROVIDER", "ollama")
    aiml_key = os.getenv("AIML_API_KEY", "")
    groq_key = os.getenv("GROQ_API_KEY", "")
    
    print(f"✓ AI_PROVIDER: {ai_provider}")
    
    if ai_provider == "aiml":
        if aiml_key:
            print(f"✓ AIML_API_KEY configurada: {aiml_key[:20]}...")
        else:
            print("❌ AIML_API_KEY NO configurada")
            return False
    elif ai_provider == "groq":
        if groq_key:
            print(f"✓ GROQ_API_KEY configurada: {groq_key[:20]}...")
        else:
            print("❌ GROQ_API_KEY NO configurada")
            return False
    else:
        print(f"⚠️  Usando Ollama local (no recomendado para Render)")
    
    return True

def probar_aiml_directamente():
    """Prueba directa a la API de AIML"""
    print("\n" + "="*60)
    print("PRUEBA DIRECTA A AIML API")
    print("="*60)
    
    aiml_key = os.getenv("AIML_API_KEY", "")
    if not aiml_key:
        print("❌ No hay AIML_API_KEY configurada")
        return False
    
    url = "https://api.aimlapi.com/chat/completions"
    headers = {
        "Authorization": f"Bearer {aiml_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "deepseek/deepseek-chat",
        "messages": [
            {"role": "system", "content": "Eres un asistente útil."},
            {"role": "user", "content": "Responde con una sola palabra: ¿Estás funcionando correctamente?"}
        ],
        "temperature": 0.7,
        "max_tokens": 50
    }
    
    try:
        print("Enviando petición a AIML API...")
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            resultado = response.json()
            mensaje = resultado["choices"][0]["message"]["content"]
            print(f"✓ Respuesta exitosa: {mensaje}")
            return True
        else:
            print(f"❌ Error {response.status_code}: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error de conexión: {e}")
        return False

def probar_endpoint_local():
    """Prueba el endpoint de tu API local"""
    print("\n" + "="*60)
    print("PRUEBA DE ENDPOINT LOCAL")
    print("="*60)
    
    # Primero necesitas obtener un token
    # Para esta prueba, vamos a asumir que tienes credenciales de prueba
    
    url = "http://localhost:8000/api/v1/ai/consulta"
    payload = {
        "pregunta": "¿Qué es una variable en programación?",
        "tema_id": "test_tema"
    }
    
    print("⚠️  Para probar el endpoint completo, necesitas:")
    print("1. Iniciar tu servidor: uvicorn main:app --reload")
    print("2. Autenticarte y obtener un token")
    print("3. Usar el token en la petición")
    print("\nEjemplo de prueba con curl:")
    print('curl -X POST "http://localhost:8000/api/v1/ai/consulta" \\')
    print('  -H "Authorization: Bearer TU_TOKEN_AQUI" \\')
    print('  -H "Content-Type: application/json" \\')
    print('  -d \'{"pregunta": "¿Qué es una variable?", "tema_id": "fundamentos_prog"}\'')

def probar_endpoint_render():
    """Muestra cómo probar el endpoint en Render"""
    print("\n" + "="*60)
    print("PRUEBA EN RENDER (PRODUCCIÓN)")
    print("="*60)
    
    print("Para probar en Render:")
    print("\n1. Ve a tu dashboard de Render")
    print("2. Busca tu servicio")
    print("3. Copia la URL (ej: https://tu-app.onrender.com)")
    print("\n4. Ejecuta este comando PowerShell:")
    print("\n$headers = @{")
    print('    "Authorization" = "Bearer TU_TOKEN_AQUI"')
    print('    "Content-Type" = "application/json"')
    print("}")
    print('$body = \'{"pregunta": "¿Qué es una variable?", "tema_id": "fundamentos_prog"}\'')
    print('Invoke-RestMethod -Uri "https://tu-app.onrender.com/api/v1/ai/consulta" -Method Post -Headers $headers -Body $body')
    
    print("\n5. O ve a los LOGS de Render:")
    print("   - Dashboard > Tu servicio > Logs")
    print("   - Busca líneas con 'IA', 'AIML', 'error'")

def verificar_codigo_main():
    """Verifica que el código de main.py tenga la configuración correcta"""
    print("\n" + "="*60)
    print("VERIFICANDO CÓDIGO main.py")
    print("="*60)
    
    try:
        with open("main.py", "r", encoding="utf-8") as f:
            contenido = f.read()
        
        # Verificar configuraciones clave
        if 'AIML_API_URL = "https://api.aimlapi.com/chat/completions"' in contenido:
            print("✓ AIML_API_URL correctamente configurada")
        else:
            print("❌ AIML_API_URL no encontrada o incorrecta")
        
        if 'meta-llama/Llama-3-8b-chat-hf' in contenido:
            print("✓ Modelo Llama-3-8b configurado")
        else:
            print("⚠️  Modelo Llama-3-8b no encontrado")
        
        if 'AI_PROVIDER = os.getenv("AI_PROVIDER"' in contenido:
            print("✓ AI_PROVIDER configurado dinámicamente")
        else:
            print("❌ AI_PROVIDER no configurado correctamente")
        
        if 'requests.post(AIML_API_URL' in contenido:
            print("✓ Llamada HTTP real a AIML API encontrada")
        else:
            print("❌ No se encontró la llamada HTTP a AIML")
        
        return True
        
    except FileNotFoundError:
        print("❌ No se encontró main.py en el directorio actual")
        return False

def main():
    """Ejecuta todas las pruebas"""
    print("\n" + "="*60)
    print("PRUEBA COMPLETA DE INTEGRACIÓN IA")
    print("="*60)
    
    # Paso 1: Verificar configuración
    if not verificar_configuracion():
        print("\n❌ Configuración incompleta. Agrega las variables de entorno necesarias.")
        return
    
    # Paso 2: Verificar código
    verificar_codigo_main()
    
    # Paso 3: Prueba directa a AIML
    if os.getenv("AI_PROVIDER") == "aiml":
        if probar_aiml_directamente():
            print("\n✅ LA IA FUNCIONA CORRECTAMENTE")
            print("La integración con AIML API está operativa.")
        else:
            print("\n❌ HAY UN PROBLEMA CON LA CONEXIÓN A AIML")
            print("Revisa tu API KEY o verifica que AIML API esté disponible")
    
    # Paso 4: Instrucciones para pruebas adicionales
    probar_endpoint_local()
    probar_endpoint_render()
    
    print("\n" + "="*60)
    print("RESUMEN")
    print("="*60)
    print("Si la prueba directa a AIML funcionó:")
    print("✓ Tu configuración es correcta")
    print("✓ Las llamadas HTTP son REALES, no simuladas")
    print("✓ El problema puede estar en el token JWT o en Render")
    print("\nSi falló:")
    print("❌ Verifica tu AIML_API_KEY")
    print("❌ Asegúrate de tener conexión a internet")
    print("❌ Revisa que api.aimlapi.com esté accesible")

if __name__ == "__main__":
    main()
