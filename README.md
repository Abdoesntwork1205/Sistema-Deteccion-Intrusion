# Sistema de Detección de Intrusiones en Redes Locales para la Contraloría Municipal de Barinas

🛡️ Sistema NIDS

Ciberseguridad: Desarrollo de un Sistema de Detección de Intrusiones en Redes (NIDS) para redes locales, empleando Machine Learning y Deep Learning mediante modelos de Redes Neuronales Recurrentes, integrado a un sistema web MERN de entrada y salida de datos.


🎯 Objetivo

Desarrollar un Sistema de Detección de Intrusiones en Redes (NIDS) orientado al monitoreo y análisis del tráfico dentro de la red local de la Contraloría Municipal de Barinas, utilizando técnicas de aprendizaje automático y aprendizaje profundo para identificar comportamientos anómalos y posibles ataques informáticos, proporcionando apoyo al análisis de seguridad informática institucional.

⚠️ Importante: el sistema no realiza monitoreo en tiempo real, ya que funciona mediante análisis de datos y simulaciones controladas con fines académicos y de evaluación de seguridad.


📋 Descripción del Sistema

Debido al creciente uso de redes informáticas dentro de instituciones públicas, aumenta la exposición a amenazas y ataques cibernéticos. Para atender esta problemática, se desarrolló un sistema capaz de detectar anomalías en el tráfico de red y alertar al usuario sobre posibles intrusiones.

El sistema utiliza el dataset NSL-KDD para el entrenamiento y evaluación de modelos de detección, empleando:


🧠 Modelos implementados:

🔹 LSTM (Long Short-Term Memory), evolución de las Redes Neuronales Recurrentes (RNN).

🔹 KNN (K-Nearest Neighbour) para clasificación.

Permitiendo:

✅ Clasificación binaria (normal o ataque)
✅ Clasificación multiclase (tipo específico de intrusión)

El usuario introduce parámetros desde una interfaz web desarrollada con ReactJS, donde el sistema analiza la información y muestra el tipo de ataque detectado junto con su descripción.


⚙️ Arquitectura tecnológica:

🍃 MongoDB como base de datos.

🚀 Node.js como backend.

🌐 ReactJS en el frontend.

🍪 Manejo de sesiones y cookies para autenticación persistente.

🔐 Autenticación mediante Google OAuth 2.0 con almacenamiento seguro mediante salted hash.


💻 Requisitos del Sistema

Para ejecutar correctamente el sistema en entorno local se requiere:

🐍 Python versión 3.10

🍃 MongoDB versión 4.4

🧭 MongoDB Compass

📦 Node.js y NPM instalados

🐳 Docker Desktop (opcional)


⚙️ Configuración Inicial

📦 Instalación de dependencias

1️⃣ Instalar paquetes del entorno web:

npm install

2️⃣ Instalar dependencias del modelo de inteligencia artificial:

pip install -r requirements.txt

🔑 Configuración del archivo .env

Crear un archivo .env en la raíz del proyecto con los siguientes parámetros:

GOOGLE_CLIENT_ID 👉 Cliente de Google Auth creado por el desarrollador.

DBLINK 👉 Conexión a la base de datos creada en MongoDB Compass.

CALLBACK_URL

http://localhost:3000/auth/google/NIDS

URL

http://localhost:3000

PORT

3000

▶️ Ejecución del Sistema

🐳 Método 1 — Docker

1️⃣ Ejecutar Docker Desktop.

2️⃣ Abrir terminal y ejecutar:

docker run --publish 3000:3000 saif0786/nids

3️⃣ Abrir en navegador:

http://localhost:3000

💻 Método 2 — Ejecución local

1️⃣ Clonar el repositorio:

git clone https://github.com/Shaik-Sohail-72/Network-Intrusion-Detection-Using-Deep-Learning.git

2️⃣ Configurar el archivo .env.

3️⃣ Instalar dependencias (npm install y pip install).

4️⃣ Ejecutar el servidor:

node app.js

5️⃣ Acceder desde el navegador:

http://localhost:3000


⚠️ Consideraciones Técnicas

📊 Sistema orientado a análisis académico y simulación de ataques en redes locales.

⏱️ No realiza monitoreo continuo en tiempo real.

🔗 Requiere configuración previa del entorno para integrar correctamente el modelo de IA con la aplicación web MERN.
