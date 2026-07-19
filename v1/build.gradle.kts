plugins {
    id("java")
}

group = "burp.extension"
version = "1.0"

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.4")
}

tasks.jar {
    manifest {
        attributes["Main-Class"] = "burp.extension.TokenScanner"
    }
}
