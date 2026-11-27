# Imagen del frontend: Node 20 en versión alpine (liviana).
FROM node:20-alpine
WORKDIR /app
# Igual que en el backend: primero copio solo package.json para que la instalación de librerías quede en caché.
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 5173
# Uso el servidor de desarrollo de Vite. "--host 0.0.0.0" es necesario para poder abrirlo desde fuera del contenedor.
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
