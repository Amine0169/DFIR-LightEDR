from fastapi.templating import Jinja2Templates

def analyst_context_processor(request):
    return {
        "user_name": "Amine Annabi",
        "user_initials": "AA",
        "user_role": "SOC Analyst",
    }

templates = Jinja2Templates(
    directory="app/templates",
    context_processors=[analyst_context_processor],
)
