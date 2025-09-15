pipeline {
    agent any
    tools {
            jdk 'JDK17'
    }
    stages {
            stage('Check Java') {
                steps {
                    sh 'java -version'
                }
            }
    }
    triggers {
        githubPush() // auto-trigger on push
    }

    stages {
        stage('Checkout') {
            steps { checkout scm }
        }

        stage('Build JAR') {
            steps {
                echo "Building project..."
                sh 'mvn clean package -DskipTests' // For Maven
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
                    // Get the author of the last commit
                    def author = sh(
                        script: "git log -1 --pretty=format:'%an <%ae>'",
                        returnStdout: true
                    ).trim()
                    echo "Commit Author: ${author}"

                    // Optional: get committer (who actually pushed)
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