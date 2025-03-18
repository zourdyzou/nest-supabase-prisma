import cluster from 'cluster';
import * as os from 'os';
import { join } from 'path';

const numCPUs = os.cpus().length;

async function bootstrap() {
  if (cluster.isPrimary) {
    console.log(`Primary ${process.pid} is running`);
    console.log(`Setting up ${numCPUs} workers...`);

    // Fork workers based on CPU count
    for (let i = 0; i < numCPUs; i++) {
      cluster.fork();
    }

    cluster.on('exit', (worker, code, signal) => {
      console.log(`Worker ${worker.process.pid} died (${signal || code}). Restarting...`);
      cluster.fork();
    });
  } else {
    // Workers can share any TCP connection
    // Import the compiled main.js file
    require(join(process.cwd(), 'dist/main'));
    console.log(`Worker ${process.pid} started`);
  }
}

bootstrap(); 