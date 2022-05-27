import vt #required to import VirusTotal python package
import os #required to access api key stored as env var
import nest_asyncio #required if you use jupyter
nest_asyncio.apply() #required if you use jupyter

vtkey = os.getenv('vtkey') #manage your secret as appropriate as you require
client = vt.Client(vtkey)

def filescan(file): #arg to be provided as string in quotes
    with open(file, 'rb') as f:
        analysis = client.scan_file(f, wait_for_completion=True)
        if analysis.stats['malicious']>0 or analysis.stats['suspicious']>0:
            return ('suspicious file')
        elif analysis.stats['failure']>0 or analysis.stats['timeout']>0 or analysis.stats['confirmed-timeout']>0:
            return ('scan failed')
        elif analysis.stats['undetected']>10:
            return ('too many undetected hits (i.e. inconclusive)')
        else:
            return ('no malicious indicator')

#analysis.stats #uncomment to see raw values

def urlscan(url): #arg to be provided as string in quotes
    url_id = vt.url_id(url)
    url = client.get_object('/urls/{}', url_id)
    if url.last_analysis_stats['malicious']>0 or analysis.stats['suspicious']>0:
        return ('suspicious file')
    elif url.last_analysis_stats['undetected'] > 10:
        return ('too many undetected hits (i.e. inconclusive)')
    elif url.last_analysis_stats['timeout']>0:
        return ('timeout')
    else:
        return ('no malicious indicator')
        
#url.last_analysis_stats #uncomment to see raw values
