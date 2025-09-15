pipeline {
    agent any

    stages {
     // Build image
        stage('Test') {
                steps {
                    echo "Testing "
                }
        }

         // Build image
        stage('Build Docker Image') {
            steps {
                sh "docker build -t spring-app:${BUILD_NUMBER} ."
            }
        }

        stage('Run Container') {
            steps {
                sh """
                # Stop and remove old spring containers if they exist
                docker rm -f spring-app-con postgres-container || true

                # Start PostgreSQL
                docker run -d --name postgres-container \
                  -e POSTGRES_DB=mydb \
                  -e POSTGRES_USER=myuser \
                  -e POSTGRES_PASSWORD=mypassword \
                  -p 5432:5432 \
                  postgres:15

                # Start Spring Boot (wait a bit for Postgres to be ready)
                sleep 10
                docker run -d --name spring-app-con \
                  --link postgres-container:postgres \
                  -p 9090:9090 \
                  -e SPRING_DATASOURCE_URL=jdbc:postgresql://postgres:5432/mydb \
                  -e SPRING_DATASOURCE_USERNAME=myuser \
                  -e SPRING_DATASOURCE_PASSWORD=mypassword \
                  spring-app:${BUILD_NUMBER}
                """
            }
        }

    }
}