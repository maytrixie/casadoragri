import pandas as pd
import numpy as np
from statsmodels.tsa.statespace.sarimax import SARIMAX
from sklearn.metrics import mean_squared_error, r2_score
import plotly.graph_objects as go

class SalesForecaster:
    def __init__(self):
        self.model = None
        self.metrics = {}
        self.forecast_values = None
        self.confidence_intervals = None
        
    def prepare_data(self, sales_data):
        """Convert sales data to proper numeric format"""
        df = pd.DataFrame(sales_data)
        
        # Convert sale_month to datetime
        df['sale_month'] = pd.to_datetime(df['sale_month'])
        
        # Ensure total_sales is numeric and handle Decimal type
        df['total_sales'] = pd.to_numeric(df['total_sales'].apply(lambda x: float(x)))
        
        # Sort by date and set index
        df = df.set_index('sale_month').sort_index()
        
        # Debug print
        print("Prepared DataFrame:")
        print(df)
        print("\nData types:")
        print(df.dtypes)
        
        return df['total_sales']

        
    def train_model(self, sales_data):
        """Train SARIMA model and calculate performance metrics"""
        data = self.prepare_data(sales_data)
        
        # Split into train/test
        train_size = int(len(data) * 0.8)
        train = data[:train_size]
        test = data[train_size:]
        
        # Fit SARIMA model
        model = SARIMAX(
            train,
            order=(1,1,1),
            seasonal_order=(1,1,1,12),
            enforce_stationarity=False
        )
        fitted_model = model.fit(disp=False)
        
        # Generate predictions
        predictions = fitted_model.predict(start=test.index[0], end=test.index[-1])
        
        # Calculate metrics
        self.metrics = {
            'rmse': np.sqrt(mean_squared_error(test, predictions)),
            'r2': r2_score(test, predictions),
            'train_size': len(train),
            'test_size': len(test)
        }
        
        self.model = fitted_model
        return fitted_model, predictions
    
    def generate_forecast(self, steps=1):  # Changed default to 1 month
        """Generate forecast with confidence intervals"""
        if not self.model:
            raise ValueError("Model not trained")
            
        forecast = self.model.get_forecast(steps=steps)
        self.forecast_values = forecast.predicted_mean
        self.confidence_intervals = forecast.conf_int()
        
        return self.forecast_values, self.confidence_intervals
    
    def plot_results(self, original_data, predictions=None, title="Monthly Sales Forecast"):
        data = self.prepare_data(original_data)
        
        fig = go.Figure()
        
        # Plot actual monthly sales
        fig.add_trace(go.Scatter(
            x=data.index,
            y=data.values,
            mode='lines+markers',
            name='Actual Sales',
            line=dict(color='blue', width=2),
            marker=dict(size=10),
            hovertemplate="<b>%{x|%B %Y}</b><br>" +
                         "Monthly Sales: ₱%{y:,.2f}<br>" +
                         "<extra></extra>"
        ))
        
        # Plot forecast for November
        if self.forecast_values is not None:
            next_month = pd.Timestamp('2025-11-01')
            forecast_value = float(self.forecast_values.iloc[0])
            ci = self.confidence_intervals.iloc[0]
            
            # Add forecast point with star marker
            fig.add_trace(go.Scatter(
                x=[next_month],
                y=[forecast_value],
                mode='markers',
                name='November Forecast',
                marker=dict(
                    color='green',
                    size=15,
                    symbol='star',
                ),
                hovertemplate="<b>November 2025 Forecast</b><br>" +
                             f"Expected Sales: ₱{forecast_value:,.2f}<br>" +
                             "<extra></extra>"
            ))
        
        # Update layout
        fig.update_layout(
            title=dict(
                text=title,
                x=0.5,
                xanchor='center',
                font=dict(size=20)
            ),
            xaxis=dict(
                title='Month',
                tickformat='%B %Y',
                tickangle=45,
                gridcolor='rgba(0,0,0,0.1)',
                tickfont=dict(size=12),
                range=[data.index[0], pd.Timestamp('2025-11-30')]  # Fixed x-axis range
            ),
            yaxis=dict(
                title='Total Sales (₱)',
                tickformat='₱,.0f',
                gridcolor='rgba(0,0,0,0.1)',
                tickfont=dict(size=12),
                range=[0, max(max(data.values), forecast_value if self.forecast_values is not None else 0) * 1.1]
            ),
            showlegend=True,
            hovermode='x unified',
            plot_bgcolor='white',
            height=500,
            margin=dict(t=100, b=100)
        )
        
        return fig