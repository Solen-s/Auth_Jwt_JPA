pipeline {
    agent any

    environment {
        JAVA_HOME = '/usr/lib/jvm/java-17-openjdk-amd64'  // Adjust this path
        PATH = "${JAVA_HOME}/bin:${env.PATH}"
    }

    triggers {
        githubPush()
    }

    stages {
        stage('Check Java') {
            steps {
                sh 'java -version'
                sh 'echo "JAVA_HOME: $JAVA_HOME"'
                sh 'which java'
            }
        }

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build JAR') {
            steps {
                echo "Building project..."
                sh 'mvn clean package -DskipTests'
            }
        }

        stage('Test') {
            steps {
                echo "Running tests..."
                sh 'mvn test'
            }
        }

        stage('Commit Info') {
            steps {
                echo "Branch: ${env.GIT_BRANCH}"
                echo "Commit: ${env.GIT_COMMIT}"

                script {
                    def author = sh(
                        script: "git log -1 --pretty=format:'%an <%ae>'",
                        returnStdout: true
                    ).trim()
                    echo "Commit Author: ${author}"

                    def committer = sh(
                        script: "git log -1 --pretty=format:'%cn <%ce>'",
                        returnStdout: true
                    ).trim()
                    echo "Committer: ${committer}"
                }
            }
        }

        stage('Build & Run Docker') {
            steps {
                script {
                    def shortCommit = sh(script: "git rev-parse --short HEAD", returnStdout: true).trim()
                    sh """
                        docker build -t backend-image:${shortCommit} .
                        docker stop backend-con || true
                        docker rm backend-con || true
                        docker run -d --name backend-con \\
                            -p 9090:9090 \\
                            -e POSTGRES_DB=mydb \\
                            -e POSTGRES_USER=postgres \\
                            -e POSTGRES_PASSWORD=postgres \\
                            backend-image:${shortCommit}
                    """
                }
            }
        }
    }

    post {
        success {
            echo "✅ Build & Deploy succeeded for commit ${env.GIT_COMMIT}"
        }
        failure {
            echo "❌ Build or Deploy failed for commit ${env.GIT_COMMIT}"
        }
    }
}