// Simple client-side polling for results
async function fetchResults(){
  try{
    const res = await fetch('/api/results');
    const data = await res.json();
    if(window.updateResults){
      window.updateResults(data);
    }
  }catch(e){
    console.error('Failed to fetch results', e);
  }
}

setInterval(fetchResults, 5000);
window.addEventListener('load', fetchResults);
