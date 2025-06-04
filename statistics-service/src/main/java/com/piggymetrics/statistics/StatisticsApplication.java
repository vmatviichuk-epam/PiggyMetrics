package com.piggymetrics.statistics;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.feign.EnableFeignClients;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

@SpringBootApplication
@EnableDiscoveryClient
@EnableFeignClients
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class StatisticsApplication {

	public static void main(String[] args) {
		SpringApplication.run(StatisticsApplication.class, args);
	}

	@Configuration
	static class CustomConversionsConfig {

		@Bean
		public org.springframework.data.mongodb.core.convert.CustomConversions customConversions() {
			return new org.springframework.data.mongodb.core.convert.CustomConversions(java.util.Arrays.asList(new com.piggymetrics.statistics.repository.converter.DataPointIdReaderConverter(),
					new com.piggymetrics.statistics.repository.converter.DataPointIdWriterConverter()));
		}
	}
}
