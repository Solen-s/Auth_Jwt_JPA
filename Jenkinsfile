pipeline {
    agent any

    stages {
        // Build Java
        stage('Build JAR') {
            steps {
                sh "mvn clean package -DskipTests=true"
            }
        }
        // Test
        stage('Test') {
            steps {
                sh "mvn test"
            }
        }

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