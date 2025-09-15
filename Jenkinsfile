pipeline {
    agent any

    stages {
     // Build image
        stage('Test') {
                steps {
                    sh "ls "
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
                if docker ps -a --format '{{.Names}}' | grep -w spring-app-container >/dev/null 2>&1; then
                    docker rm -f myapp-container
                fi
                docker run -d --name myapp-container -p 9090:9090 spring-app:${BUILD_NUMBER}
                """
            }
        }
    }
}