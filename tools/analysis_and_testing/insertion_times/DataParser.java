package programs;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

public class DataParser {

	private HashMap<Integer, Integer> times;
	
	public static void main(String[] args) {
		DataParser parser = new DataParser();
		try {
			parser.run();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void run() throws FileNotFoundException, IOException {
		times = new HashMap<Integer, Integer>();
		String[] pair;
		Integer size, time;
		int j;
		long total_time = 0;
		
		for(int i = 1; i < 100; i++) {
			try (BufferedReader br = new BufferedReader(new FileReader("C:\\Users\\Joe\\Dropbox\\final_year_project_masters\\data_collection\\insertion_times\\insertion_times2\\four_tree_slow\\output" + i + ".txt"))) {
			    String line;
			    j = 0;
			    while ((line = br.readLine()) != null) {
			    	if(j > 10000) break;
			       pair = line.split(",");
			       try {
			       size = Integer.parseInt(pair[0]);
			       time = Integer.parseInt(pair[1]);
			       } catch (Exception e) {
			    	   System.out.println("Error on output " + i + " line " + j + " (" + line + ")");
			    	   continue;
			       }
			       //if (j > 2000 && time > 2845) continue;
			       //else if (time > 1) continue;
			       if(time > 8000) continue;
			       
			       total_time += time.intValue();
			       if(times.containsKey(size)) {
			    	   times.replace(size, (times.get(size)*(i-1) + time)/i);
			       } else times.put(size, time);
			       j++;
			    }
			}
		}
		// outlierSmooth(times, 200);
		printTimes(times);
		System.out.println("Average total insertion time: " + total_time/1000 + ". Average insertion time: " + total_time/100000);
	}
	
	public void outlierSmooth(HashMap<Integer, Integer> times, int mask) {
		int i = 0, used, upper, lower;
		double outlier;
		List<Integer> list;
		
		while(i < times.size()) {
			used = 0;
			list = new ArrayList<Integer>();
			for(int j = i; j < i + mask; j++) {
				if(times.get(j) != null) {
					list.add(times.get(j));
					used++;
				}
			}
			Collections.sort(list);
			outlier = (list.get((int) (used*0.75)) + (list.get((int) (used*0.75))-list.get((int) (used*0.25)))*1.5);
			
			for(int j = i; j < i + mask; j++) {
				Integer cur = times.get(j);
				if(cur != null && cur > outlier) {
					times.remove(j);
				}
			}
			
			i += mask;
		}
	}
	
	public void averageTimes(HashMap<Integer, Integer> times, int mask) {
		int total, used;
		
		for(Integer i : times.keySet()) {
			total = 0;
			used = 0;
			for(int j = i - mask/2; j < i + mask/2; j++) {
				if(j < 0) continue;
				if(times.get(j) != null) {
					total += times.get(j);
					used++;
				}
			}
			times.replace(i, total/used);
		}
	}
	
	public void printTimes(HashMap<Integer, Integer> times) throws IOException {
		PrintWriter out = new PrintWriter(new FileWriter("C:\\Users\\Joe\\Dropbox\\final_year_project_masters\\data_collection\\insertion_times\\slow\\4_tree_averages.txt")); 
		
		List<Integer> list = new ArrayList<Integer>(times.values());
		Collections.sort(list);
		
		double average = list.stream().mapToInt(val -> val).average().getAsDouble();
		System.out.println("Average insetion time: " + average);
		System.out.println("Outlier > " + (list.get(1875) + (list.get(1875)-list.get(625))*1.5));
		// System.out.println("Outlier > " + (list.get(500 + 1500) + (list.get(500+1500)-list.get(500+500))*1.5));
		
		for(Integer i : times.keySet()) {
		//	if(i > 3000) break;
			out.println(i + "," + times.get(i));
		}
		out.close();
	}
}
