/**
 * Copyright 2004-2012 Crypto-Pro. All rights reserved.
 * Этот файл содержит информацию, являющуюся
 * собственностью компании Крипто-Про.
 *
 * Любая часть этого файла не может быть скопирована,
 * исправлена, переведена на другие языки,
 * локализована или модифицирована любым способом,
 * откомпилирована, передана по сети с или на
 * любую компьютерную систему без предварительного
 * заключения соглашения с компанией Крипто-Про.
 */
package ru.CryptoPro.CAdES.examples.speed;

import java.text.DecimalFormat;
import java.util.Calendar;
import java.util.Vector;

import ru.CryptoPro.CAdES.examples.speed.OperationManager.OperationType;

/**
 * Пример для проверки производительности различных операций с подписью CAdES:
 * создание, проверка, усовершенствование. Можно создать n потоков с выполнением
 * x идентичных операций.
 * 
 * @author Yevgeniy, 26/04/2012
 * 
 */
public class ComplexSpeedTest {

	/**
	 * Класс потока выполнения определенной операции.
	 * 
	 */
	class TestThread extends Thread {

		/**
		 * Количество итераций.
		 */
		private int iterationCount = 100;
		/**
		 * Тип выполняемой операции.
		 */
		private OperationType operationType = OperationType.otSignCadesBes;
		/**
		 * Время выполнения всех операций в потоке, мс.
		 */
		private long executionTime = 0;

		/**
		 * Конструктор.
		 * 
		 * @param count
		 *            Количество итераций в потоке.
		 */
		public TestThread(int count, OperationType otype) {

			iterationCount = count;
			operationType = otype;
		}

		/**
		 * Поточная функция, выполняющая нужную операцию нужное количество раз.
		 * 
		 */
		@Override
		public void run() {

			byte[] data = null;

			// Если собираемся проверять или усовершенствовать, то создадим одну
			// подпись подходящего типа, которую потом будем использовать.
			if (operationType == OperationType.otVerifyCadesBes
					|| operationType == OperationType.otVerifyCadesXLongType1
					|| operationType == OperationType.otEnhanceCadesBes) {

				OperationManager dataManager = null;

				switch (operationType) {

				case otVerifyCadesBes:
				case otEnhanceCadesBes: {
					dataManager = new OperationManager(
							OperationType.otSignCadesBes);
					break;
				}

				case otVerifyCadesXLongType1: {
					dataManager = new OperationManager(
							OperationType.otSignCadesXLongType1);
					break;
				}

				}

				data = dataManager.execute(null);
			}

			OperationManager operationManager = new OperationManager(
					operationType);

			// Замеряем время.
			long startTime = Calendar.getInstance().getTime().getTime();

			for (int i = 0; i < iterationCount; ++i) {
				operationManager.execute(data);
			}

			executionTime = Calendar.getInstance().getTime().getTime()
					- startTime;
		}

		/**
		 * Получение времени выполнения задания.
		 * 
		 * @return время в миллисекундах.
		 */
		public long getExecutionTime() {
			return executionTime;
		}
	}

	/**
	 * Запуск теста для проверки производительности.
	 * 
	 * @param otype
	 *            Тип операции.
	 * @param tCount
	 *            Количество потоков.
	 * @param iCount
	 *            Количество итераций в потоке.
	 */
	private void runTest(OperationType otype, int tCount, int iCount) {

		Vector<TestThread> threads = new Vector<TestThread>();

		if (iCount <= 0) {
			iCount = 1;
		}

		if (tCount <= 0) {
			tCount = 1;
		}

		try {

			// Создаем потоки.
			for (int i = 0; i < tCount; ++i) {
				threads.add(new TestThread(iCount, otype));
			}

			// Запускаем потоки.
			for (int i = 0; i < tCount; ++i) {
				threads.get(i).start();
			}

			// Ждем потоки не более 10 минут.
			for (int i = 0; i < tCount; ++i) {
				threads.get(i).join(10 * 60 * 1000);
			}

			long totalTime = 0;

			// Убиваем потоки, если еще живые.
			for (int i = 0; i < tCount; ++i) {

				if (threads.get(i).isAlive()) {
					threads.get(i).stop();
				}

				long threadTime = threads.get(i).getExecutionTime();

				// Среднее время и скорость по одному потоку.
				System.out.println("---------- Thread # " + (i + 1)
					+ " ----------");

				printInfo("Average speed of execution: ",
					(double) (iCount * 1000) / threadTime, "op/s");

				printInfo("Average time of an operation: ", (double) threadTime
					/ (iCount * 1000), "s");

				totalTime += threadTime;
			}

			// Среднее время и скорость по всем потокам.
			System.out.println("-------------------------------------");

			printTestInfo(otype, tCount, iCount);

			printInfo("Average speed of execution: ", (double) (tCount
				* iCount * 1000)
				/ totalTime, "op/s");

			printInfo("Average time of an operation: ",
				(double) totalTime / (tCount * iCount), "ms");

			printInfo("Total speed of execution: ",
				(double) (tCount * iCount * 1000) / (totalTime / tCount),
				"op/s");

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Вывод информации о результате операции.
	 * 
	 * @param message
	 *            Описание результата.
	 * @param value
	 *            Значение измеряемого параметра.
	 * @param size
	 *            Единица измерения.
	 */
	private void printInfo(String message, double value, String size) {

		DecimalFormat decFormat = new DecimalFormat("#.###");
		System.out.println(message + decFormat.format(value) + " " + size);
	}

	/**
	 * Вывод сводной информации о производительности.
	 * 
	 * @param otype Тип операции.
	 * @param tCount Количество потоков.
	 * @param iCount Количество итераций.
	 */
	private void printTestInfo(OperationType otype, int tCount, int iCount) {
		
		System.out.print("Test: ");
		
		switch (otype) {
			
			case otSignCadesBes:
				System.out.println("Sign CADES_BES");
				break;
		
			case otSignCadesXLongType1:
				System.out.println("Sign CADES_X_LONG_TYPE_1");
				break;
		
			case otVerifyCadesBes:
				System.out.println("Verify CADES_BES");
				break;
		
			case otVerifyCadesXLongType1:
				System.out.println("Verify CADES_X_LONG_TYPE_1");
				break;
				
			case otEnhanceCadesBes:
				System.out.println("Enhance CADES_BES to CADES_X_LONG_TYPE_1");
				break;
		}
		
		System.out.println("Number of threads: " + tCount);
		System.out.println("Number of iterations: " + iCount);
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		ComplexSpeedTest speedTest = new ComplexSpeedTest();

		// Пример запуска 5 потоков для 1000 операций создания подписей
		// CAdES-BES.
		speedTest.runTest(OperationType.otSignCadesBes, 5, 1000);
	}

}
