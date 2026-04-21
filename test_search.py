from search import get_search_results
results = get_search_results("hacker forum", max_workers=10)
print(f"Found {len(results)} results")
for r in results[:5]:
    print(r['link'])
