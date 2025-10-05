pipeline {
    agent any
    environment {
        EMAIL_RECIPIENT = 'solandd9@gmail.com'
        DEPLOY_ENV = 'production'
    }
    stages {
        stage('Test') {
            steps {
                echo "Testing"
            }
        }

        stage('Build') {
            steps {
                sh "docker build -t spring-app:${BUILD_NUMBER} ."
            }
        }

        stage('Run Container') {
            steps {
                sh """
                docker rm -f spring-app-con postgres-container || true

                docker run -d --name postgres-container \
                  -e POSTGRES_DB=mydb \
                  -e POSTGRES_USER=myuser \
                  -e POSTGRES_PASSWORD=mypassword \
                  -p 5432:5432 postgres

                docker run -d --name spring-app-con \
                  --link postgres-container:postgres \
                  -e SPRING_DATASOURCE_URL=jdbc:postgresql://postgres:5432/mydb \
                  -e SPRING_DATASOURCE_USERNAME=myuser \
                  -e SPRING_DATASOURCE_PASSWORD=mypassword \
                  -p 9090:9090 spring-app:${BUILD_NUMBER}
                """
            }
        }

        stage('Send Email Notification') {
            steps {
                script {
                    sh """
                    echo "Deployment to ${DEPLOY_ENV} completed successfully at \$(date)" | \
                    mail -s "Jenkins Deployment Notification" ${EMAIL_RECIPIENT}
                    """
                }
            }
        }
    }

    post {
        failure {
            script {
                sh """
                echo "Deployment FAILED at \$(date)" | \
                mail -s "Jenkins Deployment Failure" ${EMAIL_RECIPIENT}
                """
            }
        }
    }
}

