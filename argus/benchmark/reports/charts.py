class ChartGenerator:
    """Utility to generate text-based or HTML-based charts for reports."""
    
    @staticmethod
    def generate_ascii_bar(value: float, max_value: float = 100.0, width: int = 40) -> str:
        """Generates an ASCII progress bar."""
        if value < 0: value = 0
        if value > max_value: value = max_value
        
        filled = int((value / max_value) * width)
        empty = width - filled
        return f"[{'=' * filled}{' ' * empty}] {value:.2f}%"
        
    @staticmethod
    def generate_html_bar(value: float, max_value: float = 100.0) -> str:
        """Generates a simple HTML/CSS progress bar."""
        if value < 0: value = 0
        if value > max_value: value = max_value
        
        percentage = (value / max_value) * 100
        color = "#4CAF50" if percentage >= 80 else "#FF9800" if percentage >= 50 else "#F44336"
        
        return f'''
        <div style="width: 100%; background-color: #e0e0e0; border-radius: 4px; margin: 4px 0;">
            <div style="width: {percentage}%; background-color: {color}; height: 16px; border-radius: 4px;"></div>
        </div>
        '''
