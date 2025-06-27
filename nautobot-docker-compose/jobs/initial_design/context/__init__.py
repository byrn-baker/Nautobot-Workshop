from nautobot_design_builder.context import Context, context_file

@context_file("initial_data.yml")
class InitialDesignContext(Context):
    """Render context for basic design"""
    pass