import requests
import multiprocessing as mp
import time
import argparse
import os
from concurrent.futures import ThreadPoolExecutor

def check_url_range(base_url, dir_num, start_file, end_file, result_queue):
    """Check a range of URLs with the given directory number and file numbers from start to end."""
    found = []
    for file_num in range(start_file, end_file + 1):
        url = f"{base_url}/{dir_num}/{file_num}.mp4"
        try:
            response = requests.head(url, timeout=5)
            if response.status_code == 200:
                found.append(url)
                print(f"Found: {url}")
        except requests.RequestException:
            pass
    
    # Put results in the queue
    result_queue.put(found)

def process_directory(base_url, dir_num, max_file, result_queue, chunk_size=100, max_threads=10):
    """Process a specific directory number using thread pool for file numbers."""
    print(f"Process {os.getpid()} scanning directory {dir_num}...")
    
    # For larger ranges, use threading within the process
    if max_file > chunk_size:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Split the work into chunks
            chunks = []
            for start in range(1, max_file + 1, chunk_size):
                end = min(start + chunk_size - 1, max_file)
                chunks.append((start, end))
            
            # Submit each chunk to the thread pool
            futures = []
            for start, end in chunks:
                futures.append(executor.submit(
                    check_url_range, base_url, dir_num, start, end, result_queue
                ))
            
            # Wait for all futures to complete
            for future in futures:
                future.result()
    else:
        # For smaller ranges, skip the thread pool
        check_url_range(base_url, dir_num, 1, max_file, result_queue)
    
    print(f"Process {os.getpid()} for directory {dir_num} completed.")

def find_urls_multiprocessing(base_url, max_dir, max_file, max_processes=None):
    """Find all valid URLs using multiprocessing."""
    if max_processes is None:
        # Use CPU count but limit to max_dir
        max_processes = min(mp.cpu_count(), max_dir)
    
    print(f"Starting search with {max_processes} processes...")
    start_time = time.time()
    
    # Create a queue to collect results
    result_queue = mp.Queue()
    
    # Create and start processes
    processes = []
    for dir_num in range(1, max_dir + 1):
        p = mp.Process(
            target=process_directory,
            args=(base_url, dir_num, max_file, result_queue)
        )
        processes.append(p)
        p.start()
        
        # Limit the number of concurrent processes
        if len(processes) >= max_processes:
            processes[0].join()
            processes.pop(0)
    
    # Wait for remaining processes to complete
    for p in processes:
        p.join()
    
    # Collect results from the queue
    found_urls = []
    while not result_queue.empty():
        found_urls.extend(result_queue.get())
    
    elapsed = time.time() - start_time
    print(f"Search completed in {elapsed:.1f} seconds.")
    print(f"Found {len(found_urls)} valid URLs.")
    
    return found_urls

def save_urls(urls, output_file="found_urls.txt"):
    """Save found URLs to a file."""
    with open(output_file, "w") as f:
        for url in urls:
            f.write(f"{url}\n")
    print(f"URLs saved to {output_file}")

if __name__ == "__main__":
    # This is required for Windows to work properly with multiprocessing
    mp.freeze_support()
    
    parser = argparse.ArgumentParser(description="Find valid URLs following a pattern using multiprocessing.")
    parser.add_argument("--base-url", default="https://example.com/prd", help="Base URL without trailing slash")
    parser.add_argument("--max-dir", type=int, default=100, help="Maximum directory number")
    parser.add_argument("--max-file", type=int, default=100, help="Maximum file number")
    parser.add_argument("--processes", type=int, default=None, help="Number of processes (default: CPU count)")
    parser.add_argument("--output", default="found_urls.txt", help="Output file name")
    
    args = parser.parse_args()
    
    found_urls = find_urls_multiprocessing(
        args.base_url, 
        args.max_dir, 
        args.max_file, 
        args.processes
    )
    
    if found_urls:
        save_urls(found_urls, args.output)