import requests
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import re

def download_video(url, output_path):
    """Download a video from the given URL and save it to the output path."""
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()  # Raise an exception for HTTP errors
        
        total_size = int(response.headers.get('content-length', 0))
        block_size = 1024  # 1 Kibibyte
        
        with open(output_path, 'wb') as file, tqdm(
            desc=os.path.basename(output_path),
            total=total_size,
            unit='B',
            unit_scale=True,
            unit_divisor=1024,
        ) as bar:
            for data in response.iter_content(block_size):
                file.write(data)
                bar.update(len(data))
        
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error downloading {url}: {e}")
        if os.path.exists(output_path):
            os.remove(output_path)
        return False

def merge_videos(video_files, output_file):
    """Merge multiple video files into a single file using ffmpeg."""
    # Create a text file with the list of input files
    with open('filelist.txt', 'w') as f:
        for video_file in video_files:
            f.write(f"file '{video_file}'\n")
    
    # Use ffmpeg to merge the files
    command = ['ffmpeg', '-f', 'concat', '-safe', '0', '-i', 'filelist.txt', '-c', 'copy', output_file]
    
    try:
        subprocess.run(command, check=True)
        print(f"Successfully merged videos into {output_file}")
        # Clean up the temporary file list
        os.remove('filelist.txt')
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error merging videos: {e}")
        return False

def main():
    # Base URL pattern
    base_url = "https://video.oneshort.tv/prd/416/{}.mp4"
    
    # Ask user for start and end numbers
    try:
        start_num = int(input("Enter the starting number (default is 1): ") or "1")
        end_num = int(input("Enter the ending number: "))
        
        if start_num <= 0 or end_num <= 0 or start_num > end_num:
            print("Invalid range. Starting number should be positive and less than or equal to ending number.")
            return
    except ValueError:
        print("Please enter valid numbers.")
        return
    
    # Create a directory for the downloaded videos
    output_dir = "downloaded_videos"
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate URLs and output paths
    urls_and_paths = []
    for i in range(start_num, end_num + 1):
        url = base_url.format(i)
        output_path = os.path.join(output_dir, f"video_{i:03d}.mp4")
        urls_and_paths.append((url, output_path))
    
    # Download videos in parallel
    print(f"Downloading {len(urls_and_paths)} videos...")
    successful_downloads = []
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for url, output_path in urls_and_paths:
            future = executor.submit(download_video, url, output_path)
            futures.append((future, output_path))
        
        for future, output_path in futures:
            if future.result():
                successful_downloads.append(output_path)
    
    if not successful_downloads:
        print("No videos were successfully downloaded.")
        return
    
    # Sort the successful downloads by their number
    def extract_number(filename):
        match = re.search(r'_(\d+)\.mp4$', filename)
        return int(match.group(1)) if match else 0
    
    successful_downloads.sort(key=extract_number)
    
    # Ask if the user wants to merge the videos
    merge_choice = input(f"Downloaded {len(successful_downloads)} videos. Merge them into a single file? (y/n): ")
    
    if merge_choice.lower() == 'y':
        output_file = input("Enter the name for the merged file (default: merged_video.mp4): ") or "merged_video.mp4"
        if not output_file.endswith('.mp4'):
            output_file += '.mp4'
        
        merge_videos(successful_downloads, output_file)
        
        # Ask if the user wants to delete the individual files after merging
        delete_choice = input("Delete individual video files after merging? (y/n): ")
        if delete_choice.lower() == 'y':
            for file in successful_downloads:
                os.remove(file)
            print("Individual video files deleted.")
    
    print("Process completed!")

if __name__ == "__main__":
    main()